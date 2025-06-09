import os
import sqlite3
import random
import string
from flask import (
    Flask,
    request,
    render_template,
    send_file,
    abort,
    redirect,
    url_for,
    flash,
    session,
    jsonify,
)
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta, timezone
import hashlib
import re
import threading
import time
import ipaddress
from werkzeug.middleware.proxy_fix import ProxyFix
from dotenv import load_dotenv
import secrets
import logging

# Load environment variables from .env in project root
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

# configure logging
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(os.getenv("LOG_FILE", "app.log")),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)

# Configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, os.getenv("UPLOAD_FOLDER", "uploads"))
DB_PATH = os.path.join(BASE_DIR, os.getenv("DB_PATH", "file_tokens.db"))
USERS_DB_PATH = os.path.join(BASE_DIR, os.getenv("USERS_DB_PATH", "users.db"))
BANNED_DB_PATH = os.path.join(BASE_DIR, os.getenv("BANNED_DB_PATH", "banned_ips.db"))
FILE_LOGS = os.path.join(BASE_DIR, os.getenv("FILE_LOGS", "file_logs.log"))
TOKEN_LENGTH = int(os.getenv("TOKEN_LENGTH", "34"))
# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize Flask app
app = Flask(__name__)

# Generate a fresh random secret key on each startup
app.secret_key = secrets.token_urlsafe(64)
app.config.update(
    SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "True") == "True",
    SESSION_COOKIE_HTTPONLY=os.getenv("SESSION_COOKIE_HTTPONLY", "True") == "True",
    SESSION_COOKIE_SAMESITE=os.getenv("SESSION_COOKIE_SAMESITE", "Strict"),
)
# Trust proxy headers for correct scheme detection
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
# Enable CSRF protection
csrf = CSRFProtect(app)
# Security headers via Talisman
csp = {
    "default-src": ["'self'"],
    "script-src": [
        "'self'",
        "'unsafe-inline'",
        "https://unpkg.com",
    ],  # allow inline scripts and Swagger assets
    "style-src": [
        "'self'",
        "'unsafe-inline'",
        "https://unpkg.com",
    ],  # allow inline CSS and Swagger assets
    "img-src": ["'self'", "data:"],
    "frame-ancestors": ["'none'"],
}
Talisman(
    app,
    content_security_policy=csp,
    force_https=os.getenv("TALISMAN_FORCE_HTTPS", "False") == "True",
    strict_transport_security=True,
    strict_transport_security_max_age=int(
        os.getenv("TALISMAN_STRICT_SEC_MAX_AGE", "31536000")
    ),
    strict_transport_security_preload=True,
    frame_options="DENY",
)

# Print out loaded environment variables for debugging
print("Loaded environment variables:")
for key in os.environ:
    if key.startswith("SECRET_") or key.startswith("TALISMAN_"):
        print(f"{key} = {os.environ[key]}")


@app.after_request
def set_extra_security_headers(response):
    # Add COOP and COEP headers not supported by this Talisman version
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store"
    return response


# Configure rate limiter storage to avoid in-memory warning
app.config["RATELIMIT_STORAGE_URI"] = os.getenv("RATELIMIT_STORAGE_URI", "memory://")
# helper to use Cloudflare header for rate limiting
def get_client_ip():
    # Only accept requests forwarded via Cloudflare Tunnel on localhost
    if request.remote_addr != "127.0.0.1":
        logger.warning(f"Rejected non-tunnel request from {request.remote_addr}")
        abort(403)
    # Use Cloudflare header for real client IP
    cf_ip = request.headers.get("CF-Connecting-IP")
    if not cf_ip:
        logger.warning("Missing CF-Connecting-IP header on tunnel request")
        abort(400)
    return cf_ip


# initialize rate limiter without defaults; apply per-route limits using CF-Connecting-IP
limiter = Limiter(key_func=get_client_ip, default_limits=[], app=app)


def get_user_db_connection():
    conn = sqlite3.connect(USERS_DB_PATH)
    # create users table with case-sensitive username and role column
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (username TEXT COLLATE BINARY PRIMARY KEY, password TEXT, last_ip TEXT, role TEXT, api_key TEXT)"
    )
    # ensure role column exists
    try:
        conn.execute("ALTER TABLE users ADD COLUMN role TEXT")
    except sqlite3.OperationalError:
        pass
    # ensure api_key column exists
    try:
        conn.execute("ALTER TABLE users ADD COLUMN api_key TEXT")
    except sqlite3.OperationalError:
        pass
    return conn


def get_banned_db_connection():
    conn = sqlite3.connect(BANNED_DB_PATH)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS banned_ips (ip TEXT PRIMARY KEY, banned_at TEXT)"
    )
    return conn


# initialize banned IPs database
get_banned_db_connection().close()

# Database setup
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    # create table including expires_at, uploader_ip, and username
    conn.execute(
        "CREATE TABLE IF NOT EXISTS files (token TEXT PRIMARY KEY, stored_name TEXT, original_name TEXT, expires_at TEXT, uploader_ip TEXT, username TEXT)"
    )
    # add expires_at column if missing
    try:
        conn.execute("ALTER TABLE files ADD COLUMN expires_at TEXT")
    except sqlite3.OperationalError:
        pass
    # add uploader_ip column if missing
    try:
        conn.execute("ALTER TABLE files ADD COLUMN uploader_ip TEXT")
    except sqlite3.OperationalError:
        pass
    # add username column if missing
    try:
        conn.execute("ALTER TABLE files ADD COLUMN username TEXT")
    except sqlite3.OperationalError:
        pass
    # add method column if missing (stores 'Webpage' or 'API')
    try:
        conn.execute("ALTER TABLE files ADD COLUMN method TEXT")
    except sqlite3.OperationalError:
        pass
    return conn


# Generate a random token
def generate_token(length=TOKEN_LENGTH):
    chars = string.ascii_letters + string.digits
    conn = get_db_connection()
    try:
        while True:
            token = "".join(random.choice(chars) for _ in range(length))
            exists = conn.execute(
                "SELECT 1 FROM files WHERE token = ?", (token,)
            ).fetchone()
            if not exists:
                return token
    finally:
        conn.close()


@app.route("/", methods=["GET", "POST"])
@limiter.limit("20 per 1 minutes")
def upload_file():
    # require login
    if "username" not in session:
        # if AJAX call, return JSON error instead of HTML redirect
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"error": "Not authenticated"}), 401
        return redirect(url_for("login"))
    # get user role
    conn_r = get_user_db_connection()
    row_r = conn_r.execute(
        "SELECT role FROM users WHERE username = ?", (session["username"],)
    ).fetchone()
    conn_r.close()
    role = row_r[0] if row_r else "Limited"
    if "username" not in session:
        # if AJAX call, return JSON error instead of HTML redirect
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"error": "Not authenticated"}), 401
        return redirect(url_for("login"))
    elif request.method == "POST":
        # enforce max 10 active uploads for Limited users
        if role == "Limited":
            conn_count = get_db_connection()
            count = conn_count.execute(
                "SELECT COUNT(*) FROM files WHERE username = ?", (session["username"],)
            ).fetchone()[0]
            conn_count.close()
            if count >= 10:
                return render_template(
                    "upload.html",
                    error="Limited accounts can have at most 10 active uploads",
                )
        uploaded = request.files.get("file")
        logger.info(
            f"Web upload attempt: user={session.get('username')} ip={get_client_ip()} filename={uploaded.filename if uploaded else None}"
        )
        if not uploaded or uploaded.filename == "":
            return render_template("upload.html", error="No file selected")
        original_name = secure_filename(uploaded.filename)
        token = generate_token()
        stored_name = f"{token}_{original_name}"
        save_path = os.path.join(UPLOAD_FOLDER, stored_name)
        uploaded.save(save_path)
        # ensure uploaded files are not executable
        os.chmod(save_path, 0o600)
        # enforce role-based size limit
        size = os.path.getsize(save_path)
        # enforce 10MB for Limited users, 100MB for others
        if role == "Limited" and size > 10 * 1024 * 1024:
            os.remove(save_path)
            return render_template(
                "upload.html", error="File too large for Limited account (max 10MB)"
            )
        elif size > 100 * 1024 * 1024:
            os.remove(save_path)
            return render_template("upload.html", error="File too large (max 100MB)")
        # determine expiration: normalize input and handle 'Never'
        expire_option = (request.form.get("expire") or "").upper()
        if role == "Limited":
            # Limited accounts always get 1-day storage
            expires_dt = datetime.utcnow() + timedelta(days=1)
        else:
            if expire_option == "INF":
                expires_dt = None
            else:
                try:
                    days = int(expire_option)
                    expires_dt = datetime.utcnow() + timedelta(days=days)
                except (TypeError, ValueError):
                    # invalid input, treat as infinite
                    expires_dt = None
        expires_at = expires_dt.isoformat() if expires_dt else None
        # Insert record into DB with expiration, uploader IP and user
        uploader_ip = get_client_ip()
        user = session["username"]
        conn = get_db_connection()
        conn.execute(
            "INSERT INTO files (token, stored_name, original_name, expires_at, uploader_ip, username, method) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                token,
                stored_name,
                original_name,
                expires_at,
                uploader_ip,
                user,
                "Webpage",
            ),
        )
        logger.info(
            f"Web upload saved: token={token} user={user} file={original_name} path={save_path}"
        )
        conn.commit()
        conn.close()
        # Log upload
        try:
            ts = (
                datetime.utcnow()
                .replace(tzinfo=timezone.utc)
                .astimezone(timezone(timedelta(hours=2)))
                .strftime("%d-%m-%Y %H:%M GMT+2")
            )
            with open(save_path, "rb") as f:
                sha256 = hashlib.sha256(f.read()).hexdigest()
            size = os.path.getsize(save_path)
            with open(FILE_LOGS, "a") as log_f:
                log_f.write(
                    f"Upload Date: {ts} | Uploader IP: {uploader_ip} | File Name: {original_name} | SHA256: {sha256} | Size: {size} bytes\n"
                )
        except Exception:
            pass
        # generate one-time download link
        link = request.url_root.rstrip("/") + f"/download/{token}/{original_name}"
        # if AJAX request, return JSON with link
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"link": link})
        # otherwise flash and redirect to clear form
        logger.info(f"Web upload link generated: {link}")
        flash(link)
        return redirect(url_for("upload_file"))
    return render_template("upload.html")


@app.route("/download/<token>/<filename>")
@limiter.limit("20 per 2 minutes")
def download(token, filename):
    # validate token and filename formats
    if not TOKEN_REGEX.match(token):
        abort(404)
    safe_fname = secure_filename(filename)
    if filename != safe_fname:
        abort(404)
    conn = get_db_connection()
    logger.info(
        f"Download request: token={token} filename={filename} ip={get_client_ip()}"
    )
    cur = conn.execute(
        "SELECT stored_name, original_name, expires_at FROM files WHERE token = ?",
        (token,),
    )
    row = cur.fetchone()
    conn.close()
    if not row or filename != row[1]:
        abort(404)
    stored_name, original_name, expires_at = row
    # check expiration and cleanup if expired
    if expires_at:
        exp = datetime.fromisoformat(expires_at) + timedelta(hours=2)
        if datetime.utcnow() > exp:
            # remove file and DB record
            try:
                os.remove(os.path.join(UPLOAD_FOLDER, stored_name))
            except OSError:
                pass
            conn2 = get_db_connection()
            conn2.execute("DELETE FROM files WHERE token = ?", (token,))
            conn2.commit()
            conn2.close()
            abort(404)
    # stream file as raw binary to ensure exact content
    # prevent directory traversal
    base_dir = os.path.abspath(UPLOAD_FOLDER)
    file_path = os.path.abspath(os.path.join(base_dir, stored_name))
    if not file_path.startswith(base_dir + os.sep):
        abort(404)
    logger.info(f"Download serving file: {file_path}")
    return send_file(
        file_path,
        mimetype="application/octet-stream",
        as_attachment=True,
        download_name=original_name,
        conditional=False,
    )


# Validation regexes for tokens and usernames
USERNAME_PATTERN = r'^[a-z0-9]{1,150}$'
TOKEN_PATTERN = r'^[A-Za-z0-9]+$'
USERNAME_REGEX = re.compile(USERNAME_PATTERN)
TOKEN_REGEX = re.compile(TOKEN_PATTERN)

# Login routes
@app.route("/login", methods=["GET", "POST"])
@limiter.limit("100 per 5 minutes")
def login():
    if request.method == "POST":
        username = request.form.get("username", "").lower()
        # enforce username format
        if not USERNAME_REGEX.match(username):
            flash("Invalid username format")
            return render_template("login.html")
        password = request.form.get("password")
        logger.info(f"Login attempt: username={username} ip={get_client_ip()}")
        hashed = hashlib.sha256(password.encode()).hexdigest()
        conn = get_user_db_connection()
        cur = conn.execute("SELECT password FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        if row and row[0] == hashed:
            session["username"] = username
            # record client IP
            conn.execute(
                "UPDATE users SET last_ip = ? WHERE username = ?",
                (get_client_ip(), username),
            )
            # ensure user has an API key
            cur2 = conn.execute(
                "SELECT api_key FROM users WHERE username = ?", (username,)
            )
            api_row = cur2.fetchone()
            if not api_row or not api_row[0]:
                new_key = generate_token(32)
                conn.execute(
                    "UPDATE users SET api_key = ? WHERE username = ?",
                    (new_key, username),
                )
            conn.commit()
            conn.close()
            logger.info(f"Login success: username={username} ip={get_client_ip()}")
            return redirect(url_for("upload_file"))
        conn.close()
        logger.warning(f"Login failure: username={username} ip={get_client_ip()}")
        flash("Invalid username or password")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    # Protect logout with CSRF and ensure valid session
    session.clear()
    return redirect(url_for("login"))


# Admin dashboard for user and file management
@app.route("/admin", methods=["GET"])
def admin():
    # ensure session username format is valid
    if "username" in session and not USERNAME_REGEX.match(session["username"]):
        session.clear()
        return redirect(url_for("login"))
    # only admin access
    if "username" not in session or session.get("username") is None:
        logger.warning(f"Unauthorized admin access attempt by IP: {get_client_ip()}")
        return redirect(url_for("login"))
    # fetch user role
    conn_u = get_user_db_connection()
    cur_role = conn_u.execute(
        "SELECT role FROM users WHERE username = ?", (session["username"],)
    ).fetchone()
    if not cur_role or cur_role[0] != "admin":
        abort(403)
    # Display admin dashboard
    users = conn_u.execute("SELECT username, role, last_ip FROM users").fetchall()
    conn_u.close()
    conn_f = get_db_connection()
    files_records = conn_f.execute(
        "SELECT token, stored_name, original_name, expires_at, uploader_ip, username, method FROM files"
    ).fetchall()
    conn_f.close()
    # format file entries with human-readable size and expiration (show in GMT+2)
    def human_size(num):
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if num < 1024.0:
                return f"{num:.2f} {unit}"
            num /= 1024.0
        return f"{num:.2f} PB"

    formatted = []
    for token, stored_name, name, expires_at, ip, user, method in files_records:
        # compute size
        path = os.path.join(UPLOAD_FOLDER, stored_name)
        try:
            size = os.path.getsize(path)
            size_str = human_size(size)
        except OSError:
            size_str = "N/A"
        # format expiry in GMT+2
        if expires_at:
            try:
                dt = datetime.fromisoformat(expires_at)
                # interpret as UTC and convert to GMT+2
                dt = dt.replace(tzinfo=timezone.utc).astimezone(
                    timezone(timedelta(hours=2))
                )
                exp_str = dt.strftime("%d-%m-%Y %H:%M GMT+2")
            except Exception:
                exp_str = expires_at
        else:
            exp_str = "Never"
        formatted.append((token, name, size_str, exp_str, ip, user, method))
    # fetch banned IPs
    conn_b = get_banned_db_connection()
    b_rows = conn_b.execute("SELECT ip, banned_at FROM banned_ips").fetchall()
    conn_b.close()
    # format banned timestamps in GMT+2
    banned = []
    for ip, ban_ts in b_rows:
        try:
            dt = datetime.fromisoformat(ban_ts)
            # interpret as UTC and convert to GMT+2
            dt = dt.replace(tzinfo=timezone.utc).astimezone(
                timezone(timedelta(hours=2))
            )
            ts = dt.strftime("%d-%m-%Y %H:%M GMT+2")
        except Exception:
            ts = ban_ts
        banned.append((ip, ts))
    logger.info(
        f"Admin dashboard accessed by {session.get('username')} from IP {get_client_ip()}"
    )
    return render_template(
        "admin.html",
        users=users,
        files=formatted,
        banned_ips=banned,
        current_user=session.get("username"),
    )


@app.route("/admin/check")
def admin_check():
    # endpoint for client-side to verify admin access
    username = session.get("username")
    # ensure username format is valid
    if username and not USERNAME_REGEX.match(username):
        session.clear()
        return jsonify({"access": False}), 401
    if not username:
        return jsonify({"access": False}), 401
    conn = get_user_db_connection()
    row = conn.execute(
        "SELECT role FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()
    if row and row[0] == "admin":
        return jsonify({"access": True})
    logger.warning(
        f"Unauthorized admin check attempt by {username} from IP {get_client_ip()}"
    )
    return jsonify({"access": False}), 403


@app.route("/api/v1/admin/createuser", methods=["POST"])
@csrf.exempt
def API_admin_createuser():
    # authenticate admin via session or API key
    api_key = request.headers.get("X-API-Key")
    if api_key:
        conn_u = get_user_db_connection()
        urow = conn_u.execute(
            "SELECT username, role FROM users WHERE api_key = ?", (api_key,)
        ).fetchone()
        conn_u.close()
        if not urow or urow[1] != "admin":
            return jsonify({"error": "Invalid or missing API key"}), 403
        auth_user = urow[0]
    else:
        if "username" not in session:
            return jsonify({"error": "Authentication required"}), 401
        auth_user = session["username"]
        conn_u = get_user_db_connection()
        urow = conn_u.execute(
            "SELECT role FROM users WHERE username = ?", (auth_user,)
        ).fetchone()
        conn_u.close()
        if not urow or urow[0] != "admin":
            return jsonify({"error": "Forbidden"}), 403
    # perform create user as admin {auth_user}
    u = request.form.get("new_username", "").strip().lower()
    # validate username format
    if not USERNAME_REGEX.match(u):
        return jsonify({'error': 'Invalid username format'}), 400
    p = request.form.get("new_password")
    r = request.form.get("new_role")
    # ensure username and role
    if not u:
        if api_key:
            return jsonify({'error': 'Username cannot be empty'}), 400
        flash('Username cannot be empty')
        return redirect(url_for('admin'))
    if r not in ('Limited', 'user', 'admin'):
        if api_key:
            return jsonify({'error': 'Invalid role'}), 400
        flash('Invalid role')
        return redirect(url_for('admin'))
    # check if username already exists
    conn_check = get_user_db_connection()
    if conn_check.execute('SELECT 1 FROM users WHERE username = ?', (u,)).fetchone():
        conn_check.close()
        if api_key:
            return jsonify({'error': 'User already exists'}), 409
        flash('User already exists')
        return redirect(url_for('admin'))
    conn_check.close()
    hashed = hashlib.sha256(p.encode()).hexdigest()
    new_api_key = generate_token(64)
    conn_insert = get_user_db_connection()
    try:
        conn_insert.execute(
            "INSERT INTO users (username, password, role, api_key) VALUES (?, ?, ?, ?)",
            (u, hashed, r, new_api_key),
        )
        conn_insert.commit()
    except sqlite3.IntegrityError:
        conn_insert.close()
        if api_key:
            return jsonify({'error': 'User already exists'}), 409
        flash('User already exists')
        return redirect(url_for('admin'))
    finally:
        conn_insert.close()
    if api_key:
        return jsonify({'status': 'ok', 'username': u, 'api_key': new_api_key}), 201
    flash(f'User {u} created with API key: {new_api_key}')
    return redirect(url_for('admin'))


@app.route("/api/v1/admin/changerole", methods=["POST"])
@csrf.exempt
def API_admin_changerole():
    # authenticate admin via session or API key
    api_key = request.headers.get("X-API-Key")
    if api_key:
        conn_u = get_user_db_connection()
        urow = conn_u.execute(
            "SELECT username, role FROM users WHERE api_key = ?", (api_key,)
        ).fetchone()
        conn_u.close()
        if not urow or urow[1] != "admin":
            return jsonify({"error": "Invalid or missing API key"}), 403
        auth_user = urow[0]
    else:
        if "username" not in session:
            return jsonify({"error": "Authentication required"}), 401
        auth_user = session["username"]
        conn_u = get_user_db_connection()
        urow = conn_u.execute(
            "SELECT role FROM users WHERE username = ?", (auth_user,)
        ).fetchone()
        conn_u.close()
        if not urow or urow[0] != "admin":
            return jsonify({"error": "Forbidden"}), 403
    u = request.form.get('username')
    r = request.form.get('role')
    if r not in ('Limited', 'user', 'admin'):
        if api_key:
            return jsonify({'error': 'Invalid role'}), 400
        flash('Invalid role')
        return redirect(url_for('admin'))
    # update user role with a new DB connection
    conn_update = get_user_db_connection()
    conn_update.execute('UPDATE users SET role = ? WHERE username = ?', (r, u))
    conn_update.commit()
    conn_update.close()
    if api_key:
        return jsonify({'status': 'ok', 'username': u, 'new_role': r}), 200
    flash(f'Role for {u} updated')
    logger.info(f"Admin {auth_user} changed role for user={u} to role={r}")
    return redirect(url_for('admin'))


@app.route("/api/v1/admin/changepassword", methods=["POST"])
@csrf.exempt
def API_admin_changepassword():
    # authenticate admin via session or API key
    api_key = request.headers.get("X-API-Key")
    if api_key:
        conn_u = get_user_db_connection()
        urow = conn_u.execute(
            "SELECT username, role FROM users WHERE api_key = ?", (api_key,)
        ).fetchone()
        conn_u.close()
        if not urow or urow[1] != "admin":
            return jsonify({"error": "Invalid or missing API key"}), 403
        auth_user = urow[0]
    else:
        if "username" not in session:
            return jsonify({"error": "Authentication required"}), 401
        auth_user = session["username"]
        conn_u = get_user_db_connection()
        urow = conn_u.execute(
            "SELECT role FROM users WHERE username = ?", (auth_user,)
        ).fetchone()
        conn_u.close()
        if not urow or urow[0] != "admin":
            return jsonify({"error": "Forbidden"}), 403
    u = request.form.get('username')
    p = request.form.get('password')
    if not u:
        if api_key:
            return jsonify({'error': 'Username cannot be empty'}), 400
        flash('Username cannot be empty')
        return redirect(url_for('admin'))
    hashed = hashlib.sha256(p.encode()).hexdigest()
    conn_u.execute('UPDATE users SET password = ? WHERE username = ?', (hashed, u))
    conn_u.commit()
    conn_u.close()
    logger.info(f"Admin {auth_user} reset password for user={u}")
    if api_key:
        return jsonify({'status': 'ok', 'username': u}), 200
    flash(f'Password for {u} reset')    
    return redirect(url_for('admin'))


@app.route("/api/v1/admin/deleteuser", methods=["POST"])
@csrf.exempt
def API_admin_deleteuser():
    # authenticate admin via session or API key
    api_key = request.headers.get("X-API-Key")
    if api_key:
        conn_u = get_user_db_connection()
        urow = conn_u.execute(
            "SELECT username, role FROM users WHERE api_key = ?", (api_key,)
        ).fetchone()
        conn_u.close()
        if not urow or urow[1] != "admin":
            return jsonify({"error": "Invalid or missing API key"}), 403
        auth_user = urow[0]
    else:
        if "username" not in session:
            return jsonify({"error": "Authentication required"}), 401
        auth_user = session["username"]
        conn_u = get_user_db_connection()
        urow = conn_u.execute(
            "SELECT role FROM users WHERE username = ?", (auth_user,)
        ).fetchone()
        conn_u.close()
        if not urow or urow[0] != "admin":
            return jsonify({"error": "Forbidden"}), 403
    u = request.form.get('username', "").strip().lower()
    # validate username format
    if not USERNAME_REGEX.match(u):
        if api_key:
            return jsonify({'error': 'Invalid username format'}), 400
        flash('Invalid username format')
        return redirect(url_for('admin'))
    if u == session.get('username'):
        if api_key:
            return jsonify({'error': 'Cannot delete current admin'}), 400
        flash('Cannot delete current admin')
        return redirect(url_for('admin'))
    if not u:
        if api_key:
            return jsonify({'error': 'Username cannot be empty'}), 400
        flash('Username cannot be empty')
        return redirect(url_for('admin'))
    # open separate DB connection for deletion
    conn_del = get_user_db_connection()
    cursor = conn_del.execute('DELETE FROM users WHERE username = ?', (u,))
    conn_del.commit()
    if cursor.rowcount == 0:
        conn_del.close()
        if api_key:
            return jsonify({'error': 'User not found'}), 404
        flash('User not found')
        return redirect(url_for('admin'))
    conn_del.close()
    logger.info(f"Admin {auth_user} deleted user={u}")
    if api_key:
        return jsonify({'status': 'ok', 'deleted_user': u}), 200
    flash(f'User {u} deleted')
    return redirect(url_for('admin'))


@app.route("/api/v1/admin/banip", methods=["POST"])
@csrf.exempt
def API_admin_banip():
    # authenticate admin via session or API key
    api_key = request.headers.get("X-API-Key")
    if api_key:
        conn_u = get_user_db_connection()
        urow = conn_u.execute(
            "SELECT username, role FROM users WHERE api_key = ?", (api_key,)
        ).fetchone()
        conn_u.close()
        if not urow or urow[1] != "admin":
            return jsonify({"error": "Invalid or missing API key"}), 403
        auth_user = urow[0]
    else:
        if "username" not in session:
            return jsonify({"error": "Authentication required"}), 401
        auth_user = session["username"]
        conn_u = get_user_db_connection()
        urow = conn_u.execute(
            "SELECT role FROM users WHERE username = ?", (auth_user,)
        ).fetchone()
        conn_u.close()
        if not urow or urow[0] != "admin":
            return jsonify({"error": "Forbidden"}), 403
    ip_to_ban = request.form.get("ip")
    # Validate that it's a real IPv4 or IPv6 address
    try:
        ipaddress.ip_address(ip_to_ban)
    except ValueError:
        if api_key:
            return jsonify({'error': 'Invalid IP address'}), 400
        flash('Invalid IP address')
        return redirect(url_for('admin'))
    conn_b = get_banned_db_connection()
    conn_b.execute(
        'INSERT OR IGNORE INTO banned_ips (ip, banned_at) VALUES (?, ?)',
        (ip_to_ban, datetime.utcnow().isoformat()))
    conn_b.commit(); conn_b.close()
    logger.warning(f"IP banned: ip_to_ban by={session.get('username')}")
    if api_key:
        return jsonify({'status': 'ok', 'banned_ip': ip_to_ban}), 200
    flash(f'IP {ip_to_ban} banned')
    return redirect(url_for('admin'))


@app.route("/api/v1/admin/unbanip", methods=["POST"])
@csrf.exempt
def API_admin_unbanip():
    # authenticate admin via session or API key
    api_key = request.headers.get("X-API-Key")
    if api_key:
        conn_u = get_user_db_connection()
        urow = conn_u.execute(
            "SELECT username, role FROM users WHERE api_key = ?", (api_key,)
        ).fetchone()
        conn_u.close()
        if not urow or urow[1] != "admin":
            return jsonify({"error": "Invalid or missing API key"}), 403
        auth_user = urow[0]
    else:
        if "username" not in session:
            return jsonify({"error": "Authentication required"}), 401
        auth_user = session["username"]
        conn_u = get_user_db_connection()
        urow = conn_u.execute(
            "SELECT role FROM users WHERE username = ?", (auth_user,)
        ).fetchone()
        conn_u.close()
        if not urow or urow[0] != "admin":
            return jsonify({"error": "Forbidden"}), 403
    ip_to_unban = request.form.get('ip')
    conn_b = get_banned_db_connection()
    conn_b.execute('DELETE FROM banned_ips WHERE ip = ?', (ip_to_unban,))
    conn_b.commit(); conn_b.close()
    logger.warning(f"IP unbanned: {ip_to_unban} by={session.get('username')}")
    if api_key:
        return jsonify({'status': 'ok', 'unbanned_ip': ip_to_unban}), 200
    flash(f'IP {ip_to_unban} unbanned')
    return redirect(url_for('admin'))


# Requre API key for upload endpoint
@app.route("/api/v1/upload", methods=["POST"])
@csrf.exempt
@limiter.limit(
    "10 per minute",
    key_func=lambda: request.headers.get("X-API-Key") or request.args.get("X-API-Key"),
)
def API_upload():
    print("API upload request received")
    # require API key in header or query
    api_key = request.headers.get("X-API-Key") or request.args.get("X-API-Key")
    if not api_key:
        return jsonify({"error": "API key required"}), 401
    logger.info(f"API upload request: api_key={api_key} ip={get_client_ip()}")
    # validate API key and fetch user role
    conn_u = get_user_db_connection()
    row = conn_u.execute(
        "SELECT username, role FROM users WHERE api_key = ?", (api_key,)
    ).fetchone()
    conn_u.close()
    if not row:
        return jsonify({"error": "Invalid API key"}), 401
    username, role = row
    # require multipart upload
    file = request.files.get("file")
    if not file or not file.filename:
        return jsonify({"error": "No file provided"}), 400
    original_name = secure_filename(file.filename)
    token = generate_token()
    stored_name = f"{token}_{original_name}"
    save_path = os.path.join(UPLOAD_FOLDER, stored_name)
    file.save(save_path)
    # ensure uploaded files are not executable
    os.chmod(save_path, 0o600)
    # enforce size limits: Limited users max 10MB, others max 100MB
    size = os.path.getsize(save_path)
    if role == "Limited" and size > 10 * 1024 * 1024:
        os.remove(save_path)
        return jsonify({"error": "File too large for Limited account (max 10MB)"}), 413
    elif size > 100 * 1024 * 1024:
        os.remove(save_path)
        return jsonify({"error": "File too large (max 100MB)"}), 413
    # respect optional form parameter 'expire', default to 7 days, allow 'INF' for never
    expire_option = (request.form.get("expire") or "").upper()
    if expire_option == "INF":
        expires_dt = None
    else:
        try:
            expires_dt = datetime.utcnow() + timedelta(days=int(expire_option))
        except (TypeError, ValueError):
            expires_dt = datetime.utcnow() + timedelta(days=7)
    expires_at = expires_dt.isoformat() if expires_dt else None
    # record in database
    uploader_ip = get_client_ip()
    # distinguish web AJAX uploads (method Webpage) vs API clients
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    upload_method = 'Webpage' if is_ajax else 'API'
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO files (token, stored_name, original_name, expires_at, uploader_ip, username, method) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (token, stored_name, original_name, expires_at, uploader_ip, username, upload_method),
    )
    conn.commit()
    conn.close()
    # Log upload
    try:
        ts = (
            datetime.utcnow()
            .replace(tzinfo=timezone.utc)
            .astimezone(timezone(timedelta(hours=2)))
            .strftime("%d-%m-%Y %H:%M GMT+2")
        )
        with open(save_path, "rb") as f:
            sha256 = hashlib.sha256(f.read()).hexdigest()
        size = os.path.getsize(save_path)
        with open(FILE_LOGS, "a") as log_f:
            log_f.write(
                f"Upload Date: {ts} | Uploader IP: {uploader_ip} | File Name: {original_name} | SHA256: {sha256} | Size: {size} bytes\n"
            )
    except Exception:
        pass
    # return JSON link
    link = request.url_root.rstrip("/") + f"/download/{token}/{original_name}"
    logger.info(f"API upload successful: token={token} user={username} link={link}")
    return jsonify({"link": link}), 201


@app.route("/api/v1/public_upload", methods=["POST"])
@csrf.exempt
# limit public uploads to 5 per IP per day (before reading body)
@limiter.limit("10 per day")
def API_public_upload():
    # Public upload endpoint without API key, with a 5MB limit and 1 day expiration
    ip = get_client_ip()
    logger.info(
        f"Public upload request: ip={ip} filename={request.files.get('file').filename if request.files.get('file') else None}"
    )
    # reject large bodies early
    content_length = request.content_length
    if content_length is not None and content_length > 5 * 1024 * 1024:
        logger.warning(f"Public upload too large: ip={ip} size={content_length}")
        return jsonify({"error": "File too large for public upload (max 5MB)"}), 413
    conn = get_db_connection()
    # count recent public uploads for this IP within last day
    rows = conn.execute(
        "SELECT expires_at FROM files WHERE uploader_ip = ? AND method = 'Public'",
        (ip,),
    ).fetchall()
    recent_count = 0
    for (exp,) in rows:
        if exp:
            try:
                if datetime.fromisoformat(exp) > datetime.utcnow():
                    recent_count += 1
            except Exception:
                pass
    if recent_count >= 5:
        conn.close()
        return jsonify({"error": "Public uploads limited to 5 per day"}), 429
    file = request.files.get("file")
    if not file or not file.filename:
        conn.close()
        logger.warning(f"Public upload missing file: ip={ip}")
        return jsonify({"error": "No file provided"}), 400
    original_name = secure_filename(file.filename)
    token = generate_token()
    stored_name = f"{token}_{original_name}"
    save_path = os.path.join(UPLOAD_FOLDER, stored_name)
    file.save(save_path)
    # ensure uploaded files are not executable
    os.chmod(save_path, 0o600)
    logger.info(
        f"Public upload saved: token={token} file={original_name} path={save_path} ip={ip}"
    )
    # enforce public size limit
    size = os.path.getsize(save_path)
    if size > 5 * 1024 * 1024:
        os.remove(save_path)
        conn.close()
        return jsonify({"error": "File too large for public upload (max 5MB)"}), 413
    expires_at = (datetime.utcnow() + timedelta(days=1)).isoformat()
    # insert record
    # use Public API for username since public uploads don't have one
    conn.execute(
        "INSERT INTO files (token, stored_name, original_name, expires_at, uploader_ip, username, method) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (token, stored_name, original_name, expires_at, ip, "Public API", "API"),
    )
    conn.commit()
    conn.close()
    # Log upload for public API
    try:
        ts = (
            datetime.utcnow()
            .replace(tzinfo=timezone.utc)
            .astimezone(timezone(timedelta(hours=2)))
            .strftime("%d-%m-%Y %H:%M GMT+2")
        )
        with open(save_path, "rb") as f:
            sha256 = hashlib.sha256(f.read()).hexdigest()
        size = os.path.getsize(save_path)
        with open(FILE_LOGS, "a") as log_f:
            log_f.write(
                f"Upload Date: {ts} | Uploader IP: {ip} | File Name: {original_name} | SHA256: {sha256} | Size: {size} bytes\n"
            )
    except Exception:
        pass
    link = request.url_root.rstrip("/") + f"/download/{token}/{original_name}"
    logger.info(f"Public upload link generated: {link}")
    return jsonify({"link": link}), 201


@app.route("/api/v1/status", methods=["GET"])
@csrf.exempt
@limiter.limit("100 per 5 minutes")
def API_status():
    # API endpoint to check service status
    return jsonify({"status": "ok"}), 200

@app.route("/api/v1/health_check", methods=["GET"])
@csrf.exempt
@limiter.limit("100 per 5 minutes")
def API_health_check():
    logger.info("Health check requested")
    x_api_key = request.headers.get("X-API-Key")
    if not x_api_key:
        return jsonify({"error": "API key required"}), 401

    # verify API key belongs to an admin
    conn_u = get_user_db_connection()
    urow = conn_u.execute(
        "SELECT username, role FROM users WHERE api_key = ?", (x_api_key,)
    ).fetchone()
    conn_u.close()
    if not urow or urow[1] != "admin":
        return jsonify({"error": "Invalid or missing API key"}), 403
    logger.info(f"Health check by admin user: {urow[0]}")

    try:
        # check file DB
        conn1 = get_db_connection()
        conn1.close()
        # check users DB
        conn2 = get_user_db_connection()
        conn2.close()
        # check banned IPs DB
        conn3 = get_banned_db_connection()
        conn3.close()
        logger.info("Health check: databases are accessible")

        # check upload folder writability
        test_file = os.path.join(UPLOAD_FOLDER, ".healthcheck")
        with open(test_file, "w") as f:
            f.write("ok")
        os.remove(test_file)
        logger.info("Health check: upload folder is writable")

        # verify required templates exist
        templates = ["admin.html", "login.html", "swagger.html", "upload.html"]
        for t in templates:
            path = os.path.join(BASE_DIR, "templates", t)
            if not os.path.exists(path):
                raise FileNotFoundError(f"Template missing: {t}")

        return jsonify({"status": "ok"}), 200

    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({"status": "error", "error": str(e)}), 500


# Admin-only API to dump all file records
@app.route("/api/v1/admin/dumpfiles", methods=["POST"])
@csrf.exempt
@limiter.limit("10 per minute")
def API_dump_files():
    # authenticate admin via X-API-Key or session
    api_key = request.headers.get("X-API-Key")
    # detect API key and AJAX for JSON response
    api_key = request.headers.get("X-API-Key")
    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest"
    if api_key:
        conn_u = get_user_db_connection()
        urow = conn_u.execute(
            "SELECT username, role FROM users WHERE api_key = ?", (api_key,)
        ).fetchone()
        conn_u.close()
        if not urow or urow[1] != "admin":
            return jsonify({"error": "Invalid or missing API key"}), 403
        auth_user = urow[0]
    else:
        if "username" not in session:
            return jsonify({"error": "Authentication required"}), 401
        conn_u = get_user_db_connection()
        urow = conn_u.execute(
            "SELECT role FROM users WHERE username = ?", (session["username"],)
        ).fetchone()
        conn_u.close()
        if not urow or urow[0] != "admin":
            return jsonify({"error": "Forbidden"}), 403
        auth_user = session["username"]
    # fetch all file entries
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT stored_name FROM files").fetchall()
    conn.close()
    # delete files from disk
    deleted = 0
    for r in rows:
        path = os.path.join(UPLOAD_FOLDER, r["stored_name"])
        try:
            os.remove(path)
            deleted += 1
        except OSError:
            pass
    # clear files table
    conn2 = get_db_connection()
    conn2.execute("DELETE FROM files")
    conn2.commit()
    conn2.close()
    logger.info(
        f"Admin dumped and cleared {deleted} files by={auth_user} ip={get_client_ip()}"
    )
    # return JSON for API key or AJAX requests
    if api_key or is_ajax:
        return jsonify({"status": "ok", "deleted_files": deleted}), 200
    flash(f"Dumped and cleared {deleted} files")
    return redirect(url_for('admin'))


@app.context_processor
def inject_user():
    # provide is_admin, user_role, and api_key to templates
    is_admin = False
    user_role = None
    api_key = None
    username = session.get("username")
    if username:
        conn = get_user_db_connection()
        # get role
        row_role = conn.execute(
            "SELECT role FROM users WHERE username = ?", (username,)
        ).fetchone()
        # get api_key
        row_api = conn.execute(
            "SELECT api_key FROM users WHERE username = ?", (username,)
        ).fetchone()
        conn.close()
        if row_role:
            user_role = row_role[0]
            if user_role == "admin":
                is_admin = True
        if row_api:
            api_key = row_api[0]
    return dict(is_admin=is_admin, user_role=user_role, api_key=api_key)


def cleanup_worker():
    """Periodically clean up expired entries and missing files every 5 minutes."""
    while True:
        conn = get_db_connection()
        # remove orphaned files: files without a matching token in DB
        tokens = set(r[0] for r in conn.execute("SELECT token FROM files").fetchall())
        for fname in os.listdir(UPLOAD_FOLDER):
            fpath = os.path.join(UPLOAD_FOLDER, fname)
            if not os.path.isfile(fpath):
                continue
            token = fname.split("_", 1)[0]
            if token not in tokens:
                try:
                    os.remove(fpath)
                except OSError:
                    pass
        # now clean up DB-driven files
        rows = conn.execute(
            "SELECT token, stored_name, expires_at FROM files"
        ).fetchall()
        for token, stored_name, expires_at in rows:
            path = os.path.join(UPLOAD_FOLDER, stored_name)
            # remove DB entry if file missing
            if not os.path.exists(path):
                conn.execute("DELETE FROM files WHERE token = ?", (token,))
                continue
            # remove expired files
            if expires_at:
                exp = datetime.fromisoformat(expires_at)
                if datetime.utcnow() > exp:
                    try:
                        os.remove(path)
                    except OSError:
                        pass
                    conn.execute("DELETE FROM files WHERE token = ?", (token,))
        conn.commit()
        conn.close()
        time.sleep(300)  # 5 minutes


def start_cleanup_worker():
    thread = threading.Thread(target=cleanup_worker, daemon=True)
    thread.start()


# start cleanup thread on import, suitable for gunicorn
start_cleanup_worker()


@app.before_request
def block_banned_ip():
    ip = get_client_ip()
    conn = get_banned_db_connection()
    row = conn.execute("SELECT ip FROM banned_ips WHERE ip = ?", (ip,)).fetchone()
    conn.close()
    if row:
        return jsonify({"Forbidden 403": "Your IP has been banned."}), 403
    # update last_ip for authenticated user if changed
    if "username" in session:
        try:
            current_ip = get_client_ip()
            conn_u = get_user_db_connection()
            conn_u.execute(
                "UPDATE users SET last_ip = ? WHERE username = ?",
                (current_ip, session["username"]),
            )
            conn_u.commit()
            conn_u.close()
            logger.info(
                f"Updated last_ip for user={session['username']} to {current_ip}"
            )
        except Exception as e:
            logger.error(f"Error updating last_ip: {e}")


# Swagger UI and spec endpoints
@app.route("/docs")
def swagger_ui():
    return render_template("swagger.html")


@app.route("/swagger")
def swagger_alias():
    return redirect(url_for("swagger_ui"))


@app.route("/swagger.json")
def swagger_spec():
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "File Upload API", "version": "1.0.0"},
        "paths": {
            "/api/v1/upload": {
                "post": {
                    "tags": ["Public"],
                    "summary": "Upload a file",
                    "parameters": [
                        {
                            "name": "X-API-Key",
                            "in": "header",
                            "required": True,
                            "schema": {"type": "string"},
                        }
                    ],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "multipart/form-data": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "file": {"type": "string", "format": "binary"}
                                    },
                                    "required": ["file"],
                                }
                            }
                        },
                    },
                    "responses": {
                        "201": {
                            "description": "File uploaded",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {"link": {"type": "string"}},
                                    }
                                }
                            },
                        },
                        "400": {"description": "No file provided"},
                        "401": {"description": "Invalid or missing API key"},
                        "413": {"description": "File exceeds size limit"},
                    },
                }
            },
            "/api/v1/public_upload": {
                "post": {
                    "tags": ["Public"],
                    "summary": "Public upload without API key limited to 5MB",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "multipart/form-data": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "file": {"type": "string", "format": "binary"}
                                    },
                                    "required": ["file"],
                                }
                            }
                        },
                    },
                    "responses": {
                        "201": {
                            "description": "File uploaded",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {"link": {"type": "string"}},
                                    }
                                }
                            },
                        },
                        "400": {"description": "No file provided"},
                        "413": {"description": "File exceeds size limit"},
                        "429": {"description": "Public upload rate limit exceeded"},
                    },
                }
            },
            "/api/v1/status": {
                "get": {
                    "tags": ["Public"],
                    "summary": "Service status",
                    "responses": {
                        "200": {
                            "description": "Service is running",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {"status": {"type": "string"}},
                                    }
                                }
                            },
                        },
                        "429": {"description": "Too many requests"},
                    },
                }
            },
            "/api/v1/admin/createuser": {
                "post": {
                   "tags": ["Administration"],
                    "summary": "Admin: Create a new user",
                    "parameters": [
                        {
                            "name": "X-API-Key",
                            "in": "header",
                            "schema": {"type": "string"},
                            "required": True,
                        }
                    ],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/x-www-form-urlencoded": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "new_username": {"type": "string"},
                                        "new_password": {"type": "string"},
                                        "new_role": {
                                            "type": "string",
                                            "enum": ["Limited", "user", "admin"],
                                        },
                                    },
                                    "required": [
                                        "new_username",
                                        "new_password",
                                        "new_role",
                                    ],
                                }
                            }
                        },
                    },
                    "responses": {
                        "302": {"description": "Redirect to admin dashboard"},
                        "401": {"description": "Authentication required"},
                        "403": {"description": "Forbidden"},
                    },
                }
            },
            "/api/v1/admin/changerole": {
                "post": {
                   "tags": ["Administration"],
                    "summary": "Admin: Change user role",
                    "parameters": [
                        {
                            "name": "X-API-Key",
                            "in": "header",
                            "schema": {"type": "string"},
                            "required": True,
                        }
                    ],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/x-www-form-urlencoded": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "username": {"type": "string"},
                                        "role": {
                                            "type": "string",
                                            "enum": ["Limited", "user", "admin"],
                                        },
                                    },
                                    "required": ["username", "role"],
                                }
                            }
                        },
                    },
                    "responses": {
                        "302": {"description": "Redirect to admin dashboard"},
                        "401": {"description": "Authentication required"},
                        "403": {"description": "Forbidden"},
                    },
                }
            },
            "/api/v1/admin/changepassword": {
                "post": {
                   "tags": ["Administration"],
                    "summary": "Admin: Reset user password",
                    "parameters": [
                        {
                            "name": "X-API-Key",
                            "in": "header",
                            "schema": {"type": "string"},
                            "required": True,
                        }
                    ],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/x-www-form-urlencoded": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "username": {"type": "string"},
                                        "password": {"type": "string"},
                                    },
                                    "required": ["username", "password"],
                                }
                            }
                        },
                    },
                    "responses": {
                        "302": {"description": "Redirect to admin dashboard"},
                        "401": {"description": "Authentication required"},
                        "403": {"description": "Forbidden"},
                    },
                }
            },
            "/api/v1/admin/deleteuser": {
                "post": {
                   "tags": ["Administration"],
                    "summary": "Admin: Delete a user",
                    "parameters": [
                        {
                            "name": "X-API-Key",
                            "in": "header",
                            "schema": {"type": "string"},
                            "required": True,
                        }
                    ],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/x-www-form-urlencoded": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"username": {"type": "string"}},
                                    "required": ["username"],
                                }
                            }
                        },
                    },
                    "responses": {
                        "302": {"description": "Redirect to admin dashboard"},
                        "401": {"description": "Authentication required"},
                        "403": {"description": "Forbidden"},
                    },
                }
            },
            "/api/v1/admin/banip": {
                "post": {
                   "tags": ["Administration"],
                    "summary": "Admin: Ban an IP address",
                    "parameters": [
                        {
                            "name": "X-API-Key",
                            "in": "header",
                            "schema": {"type": "string"},
                            "required": True,
                        }
                    ],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/x-www-form-urlencoded": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"ip": {"type": "string"}},
                                    "required": ["ip"],
                                }
                            }
                        },
                    },
                    "responses": {
                        "302": {"description": "Redirect to admin dashboard"},
                        "401": {"description": "Authentication required"},
                        "403": {"description": "Forbidden"},
                    },
                }
            },
            "/api/v1/admin/unbanip": {
                "post": {
                   "tags": ["Administration"],
                    "summary": "Admin: Unban an IP address",
                    "parameters": [
                        {
                            "name": "X-API-Key",
                            "in": "header",
                            "schema": {"type": "string"},
                            "required": True,
                        }
                    ],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/x-www-form-urlencoded": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"ip": {"type": "string"}},
                                    "required": ["ip"],
                                }
                            }
                        },
                    },
                    "responses": {
                        "302": {"description": "Redirect to admin dashboard"},
                        "401": {"description": "Authentication required"},
                        "403": {"description": "Forbidden"},
                    },
                }
            },
            "/api/v1/admin/dumpfiles": {
                "post": {
                   "tags": ["Administration"],
                    "summary": "Admin: Delete all files and clear database",
                    "parameters": [
                        {
                            "name": "X-API-Key",
                            "in": "header",
                            "schema": {"type": "string"},
                            "required": True,
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Files deleted",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "status": {"type": "string"},
                                            "deleted_files": {"type": "integer"},
                                        },
                                    }
                                }
                            },
                        },
                        "401": {"description": "Authentication required"},
                        "403": {"description": "Forbidden"},
                    },
                }
            },
            "/api/v1/health_check": {
                "get": {
                    "tags": ["Administration"],
                    "summary": "Health check endpoint",
                    "parameters": [
                        {
                            "name": "X-API-Key",
                            "in": "header",
                            "schema": {"type": "string"},
                            "required": True,
                        }
                    ],
                    "responses": {
                        "200": {"description": "Service is healthy"},
                        "401": {"description": "API key required"},
                        "403": {"description": "Forbidden"},
                        "500": {"description": "Internal server error"},
                    },
                }
            },
        },
    }
    return jsonify(spec)
