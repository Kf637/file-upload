# File Upload Service

This repository contains a Flask-based file upload application. It allows authenticated users to upload files and generate unique download links. Administrators can manage users and files through a web dashboard.

## Features

- SQLite databases for files, users, and banned IP addresses (created automatically on startup)
- User authentication with **bcrypt** hashed passwords (with automatic migration from legacy SHA-256)
- Role-based account types (`Limited`, `user`, `admin`) controlling upload size and access
- Adjustable file expiration when uploading
- Background cleanup of expired or missing files
- IP banning support
- Rate limiting via `Flask-Limiter`
- Uses the `CF-Connecting-IP` header to obtain the real client IP when running behind a Cloudflare tunnel
- **File type validation** to block dangerous executables (.exe, .bat, .sh, etc.)
- **Cryptographically secure token generation** using the `secrets` module

## Security Features

- **Strong password hashing**: Uses bcrypt for password storage (resistant to brute-force attacks)
- **Automatic hash upgrade**: Legacy SHA-256 hashes are automatically upgraded to bcrypt on login
- **Secure token generation**: All tokens use cryptographically secure random number generation
- **File type validation**: Blocks dangerous executable file types including double extensions
- **Constant-time password comparison**: Prevents timing attacks
- **Secure session cookies**: HTTPOnly, Secure, and SameSite flags enabled
- **Content Security Policy**: Implemented via Flask-Talisman
- **CSRF protection**: Enabled for all state-changing operations

## Quick Start

1. Create and activate a Python virtual environment (optional):
   ```bash
   python -m venv venv
   source venv/bin/activate
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Start the server with Gunicorn (recommended):
   ```bash
   gunicorn app:app
   ```
   On Windows you can use `waitress-serve app:app` instead.

The first user must be created manually in the database or by adding an admin account through the admin dashboard once one exists.

The application stores uploaded files in the `uploads/` directory inside the project. Token and user information is stored in local SQLite databases.

