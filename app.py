import os
import sqlite3
import random
import string
from flask import Flask, request, render_template, send_file, abort, redirect, url_for, flash, session, jsonify
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
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'))

# configure logging
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format='%(asctime)s %(levelname)s %(name)s: %(message)s',
    handlers=[
        logging.FileHandler(os.getenv('LOG_FILE', 'app.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, os.getenv('UPLOAD_FOLDER', 'uploads'))
DB_PATH = os.path.join(BASE_DIR, os.getenv('DB_PATH', 'file_tokens.db'))
USERS_DB_PATH = os.path.join(BASE_DIR, os.getenv('USERS_DB_PATH', 'users.db'))
BANNED_DB_PATH = os.path.join(BASE_DIR, os.getenv('BANNED_DB_PATH', 'banned_ips.db'))
FILE_LOGS = os.path.join(BASE_DIR, os.getenv('FILE_LOGS', 'file_logs.log'))
TOKEN_LENGTH = int(os.getenv('TOKEN_LENGTH', '34'))
# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize Flask app
app = Flask(__name__)

# Generate a fresh random secret key on each startup
app.secret_key = secrets.token_urlsafe(64)
app.config.update(
    SESSION_COOKIE_SECURE=os.getenv('SESSION_COOKIE_SECURE', 'True') == 'True',
    SESSION_COOKIE_HTTPONLY=os.getenv('SESSION_COOKIE_HTTPONLY', 'True') == 'True',
    SESSION_COOKIE_SAMESITE=os.getenv('SESSION_COOKIE_SAMESITE', 'Strict')
)
# Trust proxy headers for correct scheme detection
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
# Enable CSRF protection
csrf = CSRFProtect(app)
# Security headers via Talisman
csp = {
    'default-src': ["'self'"],
    'script-src': ["'self'", "'unsafe-inline'", "https://unpkg.com"],  # allow inline scripts and Swagger assets
    'style-src': ["'self'", "'unsafe-inline'", "https://unpkg.com"],  # allow inline CSS and Swagger assets
    'img-src': ["'self'", 'data:'],
    'frame-ancestors': ["'none'"]
}
Talisman(
    app,
    content_security_policy=csp,
    force_https=os.getenv('TALISMAN_FORCE_HTTPS', 'False') == 'True',
    strict_transport_security=True,
    strict_transport_security_max_age=int(os.getenv('TALISMAN_STRICT_SEC_MAX_AGE', '31536000')),
    strict_transport_security_preload=True,
    frame_options='DENY'
)

# Print out loaded environment variables for debugging
print("Loaded environment variables:")
for key in os.environ:
    if key.startswith('SECRET_') or key.startswith('TALISMAN_'):
        print(f"{key} = {os.environ[key]}")

@app.after_request
def set_extra_security_headers(response):
    # Add COOP and COEP headers not supported by this Talisman version
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    response.headers['Cross-Origin-Embedder-Policy'] = 'require-corp'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Cache-Control'] = 'no-store'
    return response

# Configure rate limiter storage to avoid in-memory warning
app.config['RATELIMIT_STORAGE_URI'] = os.getenv('RATELIMIT_STORAGE_URI', 'memory://')
# helper to use Cloudflare header for rate limiting
def get_client_ip():
    # Only accept requests forwarded via Cloudflare Tunnel on localhost
    if request.remote_addr != '127.0.0.1':
        logger.warning(f"Rejected non-tunnel request from {request.remote_addr}")
        abort(403)
    # Use Cloudflare header for real client IP
    cf_ip = request.headers.get('CF-Connecting-IP')
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
        'CREATE TABLE IF NOT EXISTS users (username TEXT COLLATE BINARY PRIMARY KEY, password TEXT, last_ip TEXT, role TEXT, api_key TEXT)'
    )
    # ensure role column exists
    try:
        conn.execute('ALTER TABLE users ADD COLUMN role TEXT')
    except sqlite3.OperationalError:
        pass
    # ensure api_key column exists
    try:
        conn.execute('ALTER TABLE users ADD COLUMN api_key TEXT')
    except sqlite3.OperationalError:
        pass
    return conn

def get_banned_db_connection():
    conn = sqlite3.connect(BANNED_DB_PATH)
    conn.execute(
        'CREATE TABLE IF NOT EXISTS banned_ips (ip TEXT PRIMARY KEY, banned_at TEXT)'
    )
    return conn

# initialize banned IPs database
get_banned_db_connection().close()

# Database setup
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    # create table including expires_at, uploader_ip, and username
    conn.execute(
        'CREATE TABLE IF NOT EXISTS files (token TEXT PRIMARY KEY, stored_name TEXT, original_name TEXT, expires_at TEXT, uploader_ip TEXT, username TEXT)'
    )
    # add expires_at column if missing
    try:
        conn.execute('ALTER TABLE files ADD COLUMN expires_at TEXT')
    except sqlite3.OperationalError:
        pass
    # add uploader_ip column if missing
    try:
        conn.execute('ALTER TABLE files ADD COLUMN uploader_ip TEXT')
    except sqlite3.OperationalError:
        pass
    # add username column if missing
    try:
        conn.execute('ALTER TABLE files ADD COLUMN username TEXT')
    except sqlite3.OperationalError:
        pass
    # add method column if missing (stores 'Webpage' or 'API')
    try:
        conn.execute('ALTER TABLE files ADD COLUMN method TEXT')
    except sqlite3.OperationalError:
        pass
    return conn

# Generate a random token
def generate_token(length=TOKEN_LENGTH):
    chars = string.ascii_letters + string.digits
    conn = get_db_connection()
    try:
        while True:
            token = ''.join(random.choice(chars) for _ in range(length))
            exists = conn.execute('SELECT 1 FROM files WHERE token = ?', (token,)).fetchone()
            if not exists:
                return token
    finally:
        conn.close()

@app.route('/', methods=['GET', 'POST'])
@limiter.limit("10 per 1 minutes")
def upload_file():
    # require login
    if 'username' not in session:
        # if AJAX call, return JSON error instead of HTML redirect
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'error': 'Not authenticated'}), 401
        return redirect(url_for('login'))
    # get user role
    conn_r = get_user_db_connection()
    row_r = conn_r.execute('SELECT role FROM users WHERE username = ?', (session['username'],)).fetchone()
    conn_r.close()
    role = row_r[0] if row_r else 'Limited'
    if 'username' not in session:
        # if AJAX call, return JSON error instead of HTML redirect
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'error': 'Not authenticated'}), 401
        return redirect(url_for('login'))
    elif request.method == 'POST':
        # enforce max 10 active uploads for Limited users
        if role == 'Limited':
            conn_count = get_db_connection()
            count = conn_count.execute('SELECT COUNT(*) FROM files WHERE username = ?', (session['username'],)).fetchone()[0]
            conn_count.close()
            if count >= 10:
                return render_template('upload.html', error='Limited accounts can have at most 10 active uploads')
        uploaded = request.files.get('file')
        logger.info(f"Web upload attempt: user={session.get('username')} ip={get_client_ip()} filename={uploaded.filename if uploaded else None}")
        if not uploaded or uploaded.filename == '':
            return render_template('upload.html', error='No file selected')
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
        if role == 'Limited' and size > 10 * 1024 * 1024:
            os.remove(save_path)
            return render_template('upload.html', error='File too large for Limited account (max 10MB)')
        elif size > 100 * 1024 * 1024:
            os.remove(save_path)
            return render_template('upload.html', error='File too large (max 100MB)')
        # determine expiration: normalize input and handle 'Never'
        expire_option = (request.form.get('expire') or '').upper()
        if role == 'Limited':
            # Limited accounts always get 1-day storage
            expires_dt = datetime.utcnow() + timedelta(days=1)
        else:
            if expire_option == 'INF':
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
        user = session['username']
        conn = get_db_connection()
        conn.execute(
            'INSERT INTO files (token, stored_name, original_name, expires_at, uploader_ip, username, method) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (token, stored_name, original_name, expires_at, uploader_ip, user, 'Webpage')
        )
        logger.info(f"Web upload saved: token={token} user={user} file={original_name} path={save_path}")
        conn.commit()
        conn.close()
        # Log upload
        try:
            ts = datetime.utcnow().replace(tzinfo=timezone.utc).astimezone(timezone(timedelta(hours=2))).strftime('%d-%m-%Y %H:%M GMT+2')
            with open(save_path, 'rb') as f:
                sha256 = hashlib.sha256(f.read()).hexdigest()
            size = os.path.getsize(save_path)
            with open(FILE_LOGS, 'a') as log_f:
                log_f.write(f"Upload Date: {ts} | Uploader IP: {uploader_ip} | File Name: {original_name} | SHA256: {sha256} | Size: {size} bytes\n")
        except Exception:
            pass
        # generate one-time download link
        link = request.url_root.rstrip('/') + f"/download/{token}/{original_name}"
        # if AJAX request, return JSON with link
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'link': link})
        # otherwise flash and redirect to clear form
        logger.info(f"Web upload link generated: {link}")
        flash(link)
        return redirect(url_for('upload_file'))
    return render_template('upload.html')

@app.route('/download/<token>/<filename>')
@limiter.limit("20 per 2 minutes")
def download(token, filename):
    conn = get_db_connection()
    logger.info(f"Download request: token={token} filename={filename} ip={get_client_ip()}")
    cur = conn.execute(
        'SELECT stored_name, original_name, expires_at FROM files WHERE token = ?', (token,)
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
            conn2.execute('DELETE FROM files WHERE token = ?', (token,))
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
    return send_file(file_path,
                     mimetype='application/octet-stream',
                     as_attachment=True,
                     download_name=original_name,
                     conditional=False)

# Login routes
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("100 per 5 minutes")
def login():
    if request.method == 'POST':
        username = request.form.get('username').lower()
        password = request.form.get('password')
        logger.info(f"Login attempt: username={username} ip={get_client_ip()}")
        hashed = hashlib.sha256(password.encode()).hexdigest()
        conn = get_user_db_connection()
        cur = conn.execute('SELECT password FROM users WHERE username = ?', (username,))
        row = cur.fetchone()
        if row and row[0] == hashed:
            session['username'] = username
            # record client IP
            conn.execute('UPDATE users SET last_ip = ? WHERE username = ?', (get_client_ip(), username))
            # ensure user has an API key
            cur2 = conn.execute('SELECT api_key FROM users WHERE username = ?', (username,))
            api_row = cur2.fetchone()
            if not api_row or not api_row[0]:
                new_key = generate_token(32)
                conn.execute('UPDATE users SET api_key = ? WHERE username = ?', (new_key, username))
            conn.commit()
            conn.close()
            logger.info(f"Login success: username={username} ip={get_client_ip()}")
            return redirect(url_for('upload_file'))
        conn.close()
        logger.warning(f"Login failure: username={username} ip={get_client_ip()}")
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Admin dashboard for user and file management
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    # only admin access
    if 'username' not in session or session.get('username') is None:
        logger.warning(f"Unauthorized admin access attempt by IP: {get_client_ip()}")
        return redirect(url_for('login'))
    # fetch user role
    conn_u = get_user_db_connection()
    cur_role = conn_u.execute('SELECT role FROM users WHERE username = ?', (session['username'],)).fetchone()
    if not cur_role or cur_role[0] != 'admin':
        abort(403)
    if request.method == 'POST':
        action = request.form.get('action')
        # User management
        if action == 'create_user':
            u = request.form.get('new_username')
            p = request.form.get('new_password')
            r = request.form.get('new_role')
            # ensure username and role
            if not u:
                flash('Username cannot be empty')
            elif r not in ('Limited', 'user', 'admin'):
                flash('Invalid role')
            else:
                hashed = hashlib.sha256(p.encode()).hexdigest()
                # generate API key for new user
                new_api_key = generate_token(32)
                conn_u.execute(
                    'INSERT INTO users (username, password, role, api_key) VALUES (?, ?, ?, ?)',
                    (u, hashed, r, new_api_key)
                )
                conn_u.commit()
                logger.info(f"Admin {session.get('username')} created user={u} role={r} api_key={new_api_key}")
                flash(f'User {u} created with API key: {new_api_key}')
        elif action == 'change_role':
            u = request.form.get('username')
            r = request.form.get('role')
            # validate role
            if r not in ('Limited', 'user', 'admin'):
                flash('Invalid role')
            else:
                conn_u.execute('UPDATE users SET role = ? WHERE username = ?', (r, u))
                conn_u.commit()
                logger.info(f"Admin {session.get('username')} changed role for user={u} to role={r}")
                flash(f'Role for {u} updated')
        elif action == 'reset_password':
            u = request.form.get('username')
            p = request.form.get('password')
            # ensure username provided
            if not u:
                flash('Username cannot be empty')
            else:
                hashed = hashlib.sha256(p.encode()).hexdigest()
                conn_u.execute('UPDATE users SET password = ? WHERE username = ?', (hashed, u))
                conn_u.commit()
                logger.info(f"Admin {session.get('username')} reset password for user={u}")
                flash(f'Password for {u} reset')
        elif action == 'delete_user':
            u = request.form.get('username')
            # prevent deleting self
            if u == session.get('username'):
                flash('Cannot delete current admin')
            elif not u:
                flash('Username cannot be empty')
            else:
                conn_u.execute('DELETE FROM users WHERE username = ?', (u,))
                conn_u.commit()
                logger.info(f"Admin {session.get('username')} deleted user={u}")
                flash(f'User {u} deleted')
        # IP ban management
        if action == 'ban_ip':
            ip_to_ban = request.form.get('ip')
            # Validate that it's a real IPv4 or IPv6 address
            try:
                ipaddress.ip_address(ip_to_ban)
            except ValueError:
                flash('Invalid IP address')
                return redirect(url_for('admin'))
            conn_b = get_banned_db_connection()
            conn_b.execute('INSERT OR IGNORE INTO banned_ips (ip, banned_at) VALUES (?, ?)', (ip_to_ban, datetime.utcnow().isoformat()))
            conn_b.commit()
            conn_b.close()
            logger.warning(f"IP banned: {ip_to_ban} by={session.get('username')}")
            flash(f'IP {ip_to_ban} banned')
            return redirect(url_for('admin'))
        if action == 'unban_ip':
            ip_to_unban = request.form.get('ip')
            conn_b = get_banned_db_connection()
            conn_b.execute('DELETE FROM banned_ips WHERE ip = ?', (ip_to_unban,))
            conn_b.commit()
            conn_b.close()
            logger.warning(f"IP unbanned: {ip_to_unban} by={session.get('username')}")
            flash(f'IP {ip_to_unban} unbanned')
            return redirect(url_for('admin'))
        conn_u.close()
        # File management
        conn_f = get_db_connection()
        # SHA256 hashing of file
        if action == 'show_sha256':
            t = request.form.get('token')
            row = conn_f.execute('SELECT stored_name, original_name FROM files WHERE token = ?', (t,)).fetchone()
            if row:
                stored_name, original_name = row
                path = os.path.join(UPLOAD_FOLDER, stored_name)
                try:
                    with open(path, 'rb') as f:
                        data = f.read()
                    h = hashlib.sha256(data).hexdigest()
                    flash(f'SHA256({original_name}) = {h}')
                except Exception:
                    flash('Error calculating SHA256')
            conn_f.close()
            return redirect(url_for('admin'))
        # No SQL injection: tokens validated by DB parameterization
        if action == 'change_expiry':
            t = request.form.get('token')
            exp_option = (request.form.get('expire') or '').upper()
            if exp_option == 'INF':
                new_exp = None
            else:
                try:
                    days = int(exp_option)
                    new_exp = (datetime.utcnow() + timedelta(days=days)).isoformat()
                except (TypeError, ValueError):
                    new_exp = None
            conn_f.execute('UPDATE files SET expires_at = ? WHERE token = ?', (new_exp, t))
            conn_f.commit()
            flash(f'Expiry for {t} updated')
        elif action == 'delete_file':
            t = request.form.get('token')
            row = conn_f.execute('SELECT stored_name FROM files WHERE token = ?', (t,)).fetchone()
            if row:
                try:
                    os.remove(os.path.join(UPLOAD_FOLDER, row[0]))
                except OSError:
                    pass
                conn_f.execute('DELETE FROM files WHERE token = ?', (t,))
                conn_f.commit()
                flash(f'File {t} deleted')
        conn_f.close()
        return redirect(url_for('admin'))
    # GET: display tables
    users = conn_u.execute('SELECT username, role, last_ip FROM users').fetchall()
    conn_u.close()
    conn_f = get_db_connection()
    files_records = conn_f.execute('SELECT token, stored_name, original_name, expires_at, uploader_ip, username, method FROM files').fetchall()
    conn_f.close()
    # format file entries with human-readable size and expiration (show in GMT+2)
    def human_size(num):
        for unit in ['B','KB','MB','GB','TB']:
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
            size_str = 'N/A'
        # format expiry in GMT+2
        if expires_at:
            try:
                dt = datetime.fromisoformat(expires_at)
                # interpret as UTC and convert to GMT+2
                dt = dt.replace(tzinfo=timezone.utc).astimezone(timezone(timedelta(hours=2)))
                exp_str = dt.strftime('%d-%m-%Y %H:%M GMT+2')
            except Exception:
                exp_str = expires_at
        else:
            exp_str = 'Never'
        formatted.append((token, name, size_str, exp_str, ip, user, method))
    # fetch banned IPs
    conn_b = get_banned_db_connection()
    b_rows = conn_b.execute('SELECT ip, banned_at FROM banned_ips').fetchall()
    conn_b.close()
    # format banned timestamps in GMT+2
    banned = []
    for ip, ban_ts in b_rows:
        try:
            dt = datetime.fromisoformat(ban_ts)
            # interpret as UTC and convert to GMT+2
            dt = dt.replace(tzinfo=timezone.utc).astimezone(timezone(timedelta(hours=2)))
            ts = dt.strftime('%d-%m-%Y %H:%M GMT+2')
        except Exception:
            ts = ban_ts
        banned.append((ip, ts))
    logger.info(f"Admin dashboard accessed by {session.get('username')} from IP {get_client_ip()}")
    return render_template('admin.html', users=users, files=formatted, banned_ips=banned, current_user=session.get('username'))

@app.route('/admin/check')
def admin_check():
    # endpoint for client-side to verify admin access
    username = session.get('username')
    if not username:
        return jsonify({'access': False}), 401
    conn = get_user_db_connection()
    row = conn.execute('SELECT role FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    if row and row[0] == 'admin':
        return jsonify({'access': True})
    logger.warning(f"Unauthorized admin check attempt by {username} from IP {get_client_ip()}")
    return jsonify({'access': False}), 403

@app.route('/ban_ip', methods=['POST'])
def ban_ip():
    if 'username' not in session:
        return redirect(url_for('login'))
    conn_u = get_user_db_connection()
    row = conn_u.execute('SELECT role FROM users WHERE username = ?', (session['username'],)).fetchone()
    conn_u.close()
    if not row or row[0] != 'admin':
        abort(403)

    ip_to_ban = request.form.get('ip')
    # Validate that it's a real IPv4 or IPv6 address
    try:
        ipaddress.ip_address(ip_to_ban)
    except ValueError:
        flash('Invalid IP address')
        return redirect(url_for('admin'))

    conn_b = get_banned_db_connection()
    conn_b.execute(
        'INSERT OR IGNORE INTO banned_ips (ip, banned_at) VALUES (?, ?)',
        (ip_to_ban, datetime.utcnow().isoformat())
    )
    conn_b.commit()
    conn_b.close()
    logger.warning(f"IP banned: {ip_to_ban} by={session.get('username')}")
    flash(f'IP {ip_to_ban} banned')
    return redirect(url_for('admin'))

@app.route('/ban_ip_remove', methods=['POST'])
def ban_ip_remove():
    if 'username' not in session:
        return redirect(url_for('login'))
    conn_u = get_user_db_connection()
    row = conn_u.execute('SELECT role FROM users WHERE username = ?', (session['username'],)).fetchone()
    conn_u.close()
    if not row or row[0] != 'admin':
        abort(403)
    ip_to_unban = request.form.get('ip')
    conn_b = get_banned_db_connection()
    conn_b.execute('DELETE FROM banned_ips WHERE ip = ?', (ip_to_unban,))
    conn_b.commit()
    conn_b.close()
    logger.warning(f"IP unbanned: {ip_to_unban} by={session.get('username')}")
    flash(f'IP {ip_to_unban} unbanned')
    return redirect(url_for('admin'))

# Requre API key for upload endpoint
@app.route('/api/v1/upload', methods=['POST'])
@csrf.exempt
@limiter.limit("10 per minute", key_func=lambda: request.headers.get('X-API-Key') or request.args.get('X-API-Key'))
def API_upload():
    # require API key in header or query
    api_key = request.headers.get('X-API-Key') or request.args.get('X-API-Key')
    if not api_key:
        return jsonify({'error': 'API key required'}), 401
    logger.info(f"API upload request: api_key={api_key} ip={get_client_ip()}")
    # validate API key and fetch user role
    conn_u = get_user_db_connection()
    row = conn_u.execute('SELECT username, role FROM users WHERE api_key = ?', (api_key,)).fetchone()
    conn_u.close()
    if not row:
        return jsonify({'error': 'Invalid API key'}), 401
    username, role = row
    # require multipart upload
    file = request.files.get('file')
    if not file or not file.filename:
        return jsonify({'error': 'No file provided'}), 400
    original_name = secure_filename(file.filename)
    token = generate_token()
    stored_name = f"{token}_{original_name}"
    save_path = os.path.join(UPLOAD_FOLDER, stored_name)
    file.save(save_path)
    # ensure uploaded files are not executable
    os.chmod(save_path, 0o600)
    # enforce size limits: Limited users max 10MB, others max 100MB
    size = os.path.getsize(save_path)
    if role == 'Limited' and size > 10 * 1024 * 1024:
        os.remove(save_path)
        return jsonify({'error': 'File too large for Limited account (max 10MB)'}), 413
    elif size > 100 * 1024 * 1024:
        os.remove(save_path)
        return jsonify({'error': 'File too large (max 100MB)'}), 413
    # respect optional form parameter 'expire', default to 7 days, allow 'INF' for never
    expire_option = (request.form.get('expire') or '').upper()
    if expire_option == 'INF':
        expires_dt = None
    else:
        try:
            expires_dt = datetime.utcnow() + timedelta(days=int(expire_option))
        except (TypeError, ValueError):
            expires_dt = datetime.utcnow() + timedelta(days=7)
    expires_at = expires_dt.isoformat() if expires_dt else None
    # record in database
    uploader_ip = get_client_ip()
    conn = get_db_connection()
    conn.execute(
        'INSERT INTO files (token, stored_name, original_name, expires_at, uploader_ip, username, method) VALUES (?, ?, ?, ?, ?, ?, ?)',
        (token, stored_name, original_name, expires_at, uploader_ip, username, 'API')
    )
    conn.commit()
    conn.close()
    # Log upload
    try:
        ts = datetime.utcnow().replace(tzinfo=timezone.utc).astimezone(timezone(timedelta(hours=2))).strftime('%d-%m-%Y %H:%M GMT+2')
        with open(save_path, 'rb') as f:
            sha256 = hashlib.sha256(f.read()).hexdigest()
        size = os.path.getsize(save_path)
        with open(FILE_LOGS, 'a') as log_f:
            log_f.write(f"Upload Date: {ts} | Uploader IP: {uploader_ip} | File Name: {original_name} | SHA256: {sha256} | Size: {size} bytes\n")
    except Exception:
        pass
    # return JSON link
    link = request.url_root.rstrip('/') + f"/download/{token}/{original_name}"
    logger.info(f"API upload successful: token={token} user={username} link={link}")
    return jsonify({'link': link}), 201

@app.route('/api/v1/public_upload', methods=['POST'])
@csrf.exempt
# limit public uploads to 5 per IP per day (before reading body)
@limiter.limit("10 per day")
def API_public_upload():
    # Public upload endpoint without API key, with a 5MB limit and 1 day expiration
    ip = get_client_ip()
    logger.info(f"Public upload request: ip={ip} filename={request.files.get('file').filename if request.files.get('file') else None}")
    # reject large bodies early
    content_length = request.content_length
    if content_length is not None and content_length > 5 * 1024 * 1024:
        logger.warning(f"Public upload too large: ip={ip} size={content_length}")
        return jsonify({'error': 'File too large for public upload (max 5MB)'}), 413
    conn = get_db_connection()
    # count recent public uploads for this IP within last day
    rows = conn.execute("SELECT expires_at FROM files WHERE uploader_ip = ? AND method = 'Public'", (ip,)).fetchall()
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
        return jsonify({'error': 'Public uploads limited to 5 per day'}), 429
    file = request.files.get('file')
    if not file or not file.filename:
        conn.close()
        logger.warning(f"Public upload missing file: ip={ip}")
        return jsonify({'error': 'No file provided'}), 400
    original_name = secure_filename(file.filename)
    token = generate_token()
    stored_name = f"{token}_{original_name}"
    save_path = os.path.join(UPLOAD_FOLDER, stored_name)
    file.save(save_path)
    # ensure uploaded files are not executable
    os.chmod(save_path, 0o600)
    logger.info(f"Public upload saved: token={token} file={original_name} path={save_path} ip={ip}")
    # enforce public size limit
    size = os.path.getsize(save_path)
    if size > 5 * 1024 * 1024:
        os.remove(save_path)
        conn.close()
        return jsonify({'error': 'File too large for public upload (max 5MB)'}), 413
    expires_at = (datetime.utcnow() + timedelta(days=1)).isoformat()
    # insert record
    # use Public API for username since public uploads don't have one
    conn.execute(
        'INSERT INTO files (token, stored_name, original_name, expires_at, uploader_ip, username, method) VALUES (?, ?, ?, ?, ?, ?, ?)',
        (token, stored_name, original_name, expires_at, ip, 'Public API', 'API')
    )
    conn.commit()
    conn.close()
    # Log upload for public API
    try:
        ts = datetime.utcnow().replace(tzinfo=timezone.utc).astimezone(timezone(timedelta(hours=2))).strftime('%d-%m-%Y %H:%M GMT+2')
        with open(save_path, 'rb') as f:
            sha256 = hashlib.sha256(f.read()).hexdigest()
        size = os.path.getsize(save_path)
        with open(FILE_LOGS, 'a') as log_f:
            log_f.write(f"Upload Date: {ts} | Uploader IP: {ip} | File Name: {original_name} | SHA256: {sha256} | Size: {size} bytes\n")
    except Exception:
        pass
    link = request.url_root.rstrip('/') + f"/download/{token}/{original_name}"
    logger.info(f"Public upload link generated: {link}")
    return jsonify({'link': link}), 201

@app.route('/api/v1/status', methods=['GET'])
@csrf.exempt
@limiter.limit("100 per 5 minutes")
def API_status():
    # API endpoint to check service status
    return jsonify({
        'status': 'ok'
    }), 200

@app.context_processor
def inject_user():
    # provide is_admin, user_role, and api_key to templates
    is_admin = False
    user_role = None
    api_key = None
    username = session.get('username')
    if username:
        conn = get_user_db_connection()
        # get role
        row_role = conn.execute('SELECT role FROM users WHERE username = ?', (username,)).fetchone()
        # get api_key
        row_api = conn.execute('SELECT api_key FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        if row_role:
            user_role = row_role[0]
            if user_role == 'admin':
                is_admin = True
        if row_api:
            api_key = row_api[0]
    return dict(is_admin=is_admin, user_role=user_role, api_key=api_key)

def cleanup_worker():
    """Periodically clean up expired entries and missing files every 5 minutes."""
    while True:
        conn = get_db_connection()
        # remove orphaned files: files without a matching token in DB
        tokens = set(r[0] for r in conn.execute('SELECT token FROM files').fetchall())
        for fname in os.listdir(UPLOAD_FOLDER):
            fpath = os.path.join(UPLOAD_FOLDER, fname)
            if not os.path.isfile(fpath):
                continue
            token = fname.split('_', 1)[0]
            if token not in tokens:
                try:
                    os.remove(fpath)
                except OSError:
                    pass
        # now clean up DB-driven files
        rows = conn.execute('SELECT token, stored_name, expires_at FROM files').fetchall()
        for token, stored_name, expires_at in rows:
            path = os.path.join(UPLOAD_FOLDER, stored_name)
            # remove DB entry if file missing
            if not os.path.exists(path):
                conn.execute('DELETE FROM files WHERE token = ?', (token,))
                continue
            # remove expired files
            if expires_at:
                exp = datetime.fromisoformat(expires_at)
                if datetime.utcnow() > exp:
                    try:
                        os.remove(path)
                    except OSError:
                        pass
                    conn.execute('DELETE FROM files WHERE token = ?', (token,))
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
    row = conn.execute('SELECT ip FROM banned_ips WHERE ip = ?', (ip,)).fetchone()
    conn.close()
    if row:
        return jsonify({'Forbidden 403': 'Your IP has been banned.'}), 403

# Swagger UI and spec endpoints
@app.route('/docs')
def swagger_ui():
    return render_template('swagger.html')
@app.route('/swagger')
def swagger_alias():
    return redirect(url_for('swagger_ui'))

@app.route('/swagger.json')
def swagger_spec():
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "File Upload API", "version": "1.0.0"},
        "paths": {
            "/api/v1/upload": {
                "post": {
                    "summary": "Upload a file",
                    "parameters": [
                        {"name": "X-API-Key", "in": "header", "required": True, "schema": {"type": "string"}}
                    ],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "multipart/form-data": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"file": {"type": "string", "format": "binary"}},
                                    "required": ["file"]
                                }
                            }
                        }
                    },
                    "responses": {
                        "201": {"description": "File uploaded", "content": {"application/json": {"schema": {"type": "object", "properties": {"link": {"type": "string"}}}}}},
                        "400": {"description": "No file provided"},
                        "401": {"description": "Invalid or missing API key"},
                        "413": {"description": "File exceeds size limit"}
                    }
                }
            },
            "/api/v1/public_upload": {
                "post": {
                    "summary": "Public upload without API key limited to 5MB",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "multipart/form-data": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"file": {"type": "string", "format": "binary"}},
                                    "required": ["file"]
                                }
                            }
                        }
                    },
                    "responses": {
                        "201": {"description": "File uploaded", "content": {"application/json": {"schema": {"type": "object", "properties": {"link": {"type": "string"}}}}}},
                        "400": {"description": "No file provided"},
                        "413": {"description": "File exceeds size limit"},
                        "429": {"description": "Public upload rate limit exceeded"}
                    }
                }
            },
            "/api/v1/status": {
                "get": {
                    "summary": "Service status",
                    "responses": {
                        "200": {"description": "Service is running", "content": {"application/json": {"schema": {"type": "object", "properties": {"status": {"type": "string"}}}}}},
                        "429": {"description": "Too many requests"}
                    }
                }
            }
        }
    }
    return jsonify(spec)

# Note: use gunicorn (`gunicorn app:app`) to serve this app in production, do not use Flask's dev server
