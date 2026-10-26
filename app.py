import os
import re
import ipaddress
import sqlite3
import secrets
import hashlib
from datetime import datetime, timezone
from urllib.parse import urlparse, unquote

from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-only-change-this-secret-key")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.getenv("COOKIE_SECURE", "0") == "1"
DATABASE = os.getenv("DATABASE_PATH", "url_checker.db")

SUSPICIOUS_WORDS = {
    "login", "verify", "update", "secure", "account", "password", "banking",
    "confirm", "signin", "wallet", "free", "gift", "prize", "urgent",
    "recover", "authenticate", "limited", "suspend", "invoice"
}
RISKY_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".msi", ".apk", ".ps1", ".jar"
}
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rebrand.ly",
    "ow.ly", "buff.ly", "shorturl.at", "rb.gy"
}
TRUSTED_EXAMPLES = {"example.com", "www.example.com", "iana.org", "www.iana.org"}


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DATABASE)
    db.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        url TEXT NOT NULL,
        risk_score INTEGER NOT NULL,
        verdict TEXT NOT NULL,
        findings TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )""")
    db.commit()
    db.close()


def normalize_url(raw):
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("Enter a URL to scan.")
    if len(raw) > 2048:
        raise ValueError("URL is too long (maximum 2048 characters).")
    if any(ord(ch) < 32 for ch in raw):
        raise ValueError("URL contains control characters.")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        raw = "https://" + raw
    parsed = urlparse(raw)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are supported.")
    if not parsed.hostname:
        raise ValueError("That URL does not contain a valid hostname.")
    try:
        parsed.port
    except ValueError:
        raise ValueError("URL contains an invalid port.")
    if parsed.username or parsed.password:
        # Accepted for analysis, but marked as a strong warning below.
        pass
    try:
        host = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError:
        raise ValueError("Hostname could not be parsed.")
    if not host or " " in host:
        raise ValueError("Invalid hostname.")
    return raw, parsed._replace(netloc=parsed.netloc), host


def analyze_url(raw):
    normalized, parsed, host = normalize_url(raw)
    findings = []
    score = 0

    def add(points, severity, title, detail):
        nonlocal score
        score += points
        findings.append({
            "points": points, "severity": severity,
            "title": title, "detail": detail
        })

    if parsed.scheme.lower() != "https":
        add(15, "warning", "No HTTPS", "The URL uses HTTP, so the connection may not be encrypted.")
    else:
        findings.append({"points": 0, "severity": "good", "title": "HTTPS scheme", "detail": "The URL uses HTTPS; this alone does not prove the site is safe."})

    try:
        ipaddress.ip_address(host.strip("[]"))
        add(20, "warning", "IP address as host", "The URL uses a raw IP address instead of a conventional domain name.")
    except ValueError:
        pass

    if "@" in parsed.netloc:
        add(25, "danger", "At-sign in authority", "The @ symbol can disguise the actual destination in a URL.")
    if parsed.username or parsed.password:
        add(25, "danger", "Embedded credentials", "The URL contains user-info before the hostname. Do not enter passwords into URLs.")
    if host.startswith("xn--") or ".xn--" in host:
        add(20, "warning", "Punycode hostname", "Internationalized hostname encoding can be used in lookalike-domain attacks.")
    if len(host) > 45:
        add(10, "warning", "Long hostname", "Unusually long hostnames can be harder to inspect.")
    if host.count(".") >= 4:
        add(10, "warning", "Many subdomains", "The hostname has several subdomain levels; inspect the registered domain carefully.")
    if host.count("-") >= 3:
        add(8, "warning", "Many hyphens", "Multiple hyphens can be a sign of a lookalike or throwaway domain.")
    if any(ch.isdigit() for ch in host) and any(ch.isalpha() for ch in host):
        # Mild signal only; many legitimate domains contain digits.
        add(3, "info", "Mixed letters and digits", "The hostname mixes letters and digits. This is a weak signal and common on legitimate sites too.")
    if host in SHORTENERS:
        add(15, "warning", "URL shortener", "Shortened URLs hide their final destination; verify the destination independently.")
    decoded = unquote((parsed.path or "") + "?" + (parsed.query or "")).lower()
    matched_words = sorted(word for word in SUSPICIOUS_WORDS if word in decoded or word in host)
    if matched_words:
        add(min(25, 5 + 3 * len(matched_words)), "warning", "Suspicious keywords", "Found: " + ", ".join(matched_words) + ". These words can appear on legitimate pages too.")
    path_lower = (parsed.path or "").lower()
    if any(path_lower.endswith(ext) for ext in RISKY_EXTENSIONS):
        add(25, "danger", "Potentially executable file", "The path ends in a file extension often used for executable or script files.")
    if len(normalized) > 150:
        add(8, "info", "Long URL", "Long URLs can hide confusing paths or parameters.")
    if "%" in normalized and re.search(r"%[0-9a-fA-F]{2}", normalized):
        add(5, "info", "Encoded characters", "The URL includes percent-encoded characters. Inspect the decoded destination carefully.")
    if host in TRUSTED_EXAMPLES:
        findings.append({"points": 0, "severity": "info", "title": "Example domain", "detail": "This is a known example/test domain; the checker still does not certify safety."})

    score = min(100, score)
    if score >= 60:
        verdict, label, summary = "High Risk", "danger", "Several risk indicators were found. Avoid opening it unless verified through a trusted channel."
    elif score >= 30:
        verdict, label, summary = "Suspicious", "warning", "Some risk indicators were found. Verify the domain and destination before interacting."
    else:
        verdict, label, summary = "Low Signals", "good", "Few heuristic indicators were found. This is not proof that the URL is safe."
    return {
        "url": normalized, "host": host, "scheme": parsed.scheme.lower(),
        "score": score, "verdict": verdict, "label": label,
        "summary": summary, "findings": findings,
        "checked_at": datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    }


def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


@app.context_processor
def inject_template_vars():
    return {"csrf_token": csrf_token(), "current_user": session.get("user")}


@app.before_request
def protect_post_requests():
    if request.method == "POST":
        sent = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not sent or not expected or not secrets.compare_digest(sent, expected):
            return "Invalid or expired form token. Refresh the page and try again.", 400


@app.route("/")
def index():
    if session.get("user"):
        return redirect(url_for("dashboard"))
    return render_template("landing.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,24}", username):
            flash("Username must be 3–24 characters (letters, numbers, _, . or -).", "error")
            return render_template("register.html")
        if len(email) > 254 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            flash("Enter a valid email address.", "error")
            return render_template("register.html")
        if len(password) < 10:
            flash("Use a password with at least 10 characters.", "error")
            return render_template("register.html")
        db = get_db()
        try:
            db.execute(
                "INSERT INTO users(username,email,password_hash,created_at) VALUES(?,?,?,?)",
                (username, email, generate_password_hash(password), datetime.now(timezone.utc).isoformat())
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash("That username or email is already registered.", "error")
            return render_template("register.html")
        flash("Account created. You can now sign in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        identity = request.form.get("identity", "").strip().lower()
        password = request.form.get("password", "")
        user = get_db().execute(
            "SELECT * FROM users WHERE lower(username)=? OR email=?",
            (identity, identity)
        ).fetchone()
        if not user or not check_password_hash(user["password_hash"], password):
            flash("Incorrect username/email or password.", "error")
            return render_template("login.html")
        session.clear()
        session["user"] = {"id": user["id"], "username": user["username"], "email": user["email"]}
        session["csrf_token"] = secrets.token_urlsafe(32)
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("index"))


def login_required(view):
    from functools import wraps
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user"):
            flash("Please sign in to access your dashboard.", "info")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    uid = session["user"]["id"]
    scans = db.execute(
        "SELECT * FROM scans WHERE user_id=? ORDER BY id DESC LIMIT 10", (uid,)
    ).fetchall()
    stats = db.execute(
        """SELECT COUNT(*) AS total,
        SUM(CASE WHEN verdict='High Risk' THEN 1 ELSE 0 END) AS high,
        SUM(CASE WHEN verdict='Suspicious' THEN 1 ELSE 0 END) AS suspicious
        FROM scans WHERE user_id=?""", (uid,)
    ).fetchone()
    return render_template("dashboard.html", scans=scans, stats=stats, result=None)


@app.route("/scan", methods=["POST"])
@login_required
def scan():
    raw = request.form.get("url", "")
    try:
        result = analyze_url(raw)
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("dashboard"))
    uid = session["user"]["id"]
    db = get_db()
    db.execute(
        "INSERT INTO scans(user_id,url,risk_score,verdict,findings,created_at) VALUES(?,?,?,?,?,?)",
        (uid, result["url"], result["score"], result["verdict"],
         " | ".join(f'{x["title"]}: {x["detail"]}' for x in result["findings"]),
         datetime.now(timezone.utc).isoformat())
    )
    db.commit()
    scans = db.execute("SELECT * FROM scans WHERE user_id=? ORDER BY id DESC LIMIT 10", (uid,)).fetchall()
    stats = db.execute(
        """SELECT COUNT(*) AS total,
        SUM(CASE WHEN verdict='High Risk' THEN 1 ELSE 0 END) AS high,
        SUM(CASE WHEN verdict='Suspicious' THEN 1 ELSE 0 END) AS suspicious
        FROM scans WHERE user_id=?""", (uid,)
    ).fetchone()
    return render_template("dashboard.html", scans=scans, stats=stats, result=result)


@app.route("/history")
@login_required
def history():
    scans = get_db().execute(
        "SELECT * FROM scans WHERE user_id=? ORDER BY id DESC LIMIT 100",
        (session["user"]["id"],)
    ).fetchall()
    return render_template("history.html", scans=scans)


@app.route("/profile")
@login_required
def profile():
    user = get_db().execute("SELECT username,email,created_at FROM users WHERE id=?",
                            (session["user"]["id"],)).fetchone()
    return render_template("profile.html", user=user)


@app.errorhandler(404)
def not_found(_error):
    return render_template("404.html"), 404


init_db()

if __name__ == "__main__":
    # Local development only. For deployment, use a production WSGI server.
    app.run(debug=os.getenv("FLASK_DEBUG", "0") == "1", host="127.0.0.1", port=5000)
