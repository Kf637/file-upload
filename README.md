# File Upload Service

This repository contains a Flask-based file upload application. It allows authenticated users to upload files and generate unique download links. Administrators can manage users and files through a web dashboard.

## Features

- SQLite databases for files, users, and banned IP addresses (created automatically on startup)
- User authentication with SHA‑256 hashed passwords
- Role-based account types (`Limited`, `user`, `admin`) controlling upload size and access
- Adjustable file expiration when uploading
- Background cleanup of expired or missing files
- IP banning support
- Rate limiting via `Flask-Limiter`
- Uses the `CF-Connecting-IP` header to obtain the real client IP when running behind a Cloudflare tunnel

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

