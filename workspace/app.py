"""
AppSec Lab — workspace/app.py
==============================
This is your working file for all labs.
Use GitHub Copilot to generate each route/function as instructed
in the challenge cards, then identify and fix the vulnerabilities.
"""

import sqlite3
import bcrypt
from flask import Flask, g, request

app = Flask(__name__)
app.config["DATABASE"] = "users.db"
app.config["SECRET_KEY"] = "change-me-in-production"


# ── Database helpers ────────────────────────────────────────────────────────


_db_connection = None


def get_db():
    """Return a database connection, creating one if needed."""
    global _db_connection
    if _db_connection is None:
        _db_connection = sqlite3.connect(
            app.config["DATABASE"], detect_types=sqlite3.PARSE_DECLTYPES
        )
        _db_connection.row_factory = sqlite3.Row
    return _db_connection


def init_db():
    """Create tables if they don't exist."""
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS invoices (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id  TEXT NOT NULL,
            amount   REAL NOT NULL,
            details  TEXT
        );
    """)
    db.commit()


@app.teardown_appcontext
def close_db(error):
    if not app.config.get("TESTING"):
        global _db_connection
        if _db_connection is not None:
            _db_connection.close()
            _db_connection = None


# ── Lab 01: SQL Injection ────────────────────────────────────────────────────
# Ask Copilot: "Write a Flask POST /login route that checks a username
#               and password against a SQLite database called users.db"
# Paste Copilot's code below this comment, then find and fix the vulnerability.


# YOUR CODE HERE
@app.route("/login", methods=["POST"])
def authenticate_user():
    creds = request.form
    uname = creds.get("username", "")
    pwd = creds.get("password", "")

    if not uname or not pwd:
        return "Missing fields", 400

    conn = get_db()
    row = conn.execute(
        "SELECT username, password FROM users WHERE username = ?", (uname,)
    ).fetchone()

    stored = row["password"] if row else None
    if stored is None:
        return "Invalid credentials", 401

    hashed = stored if isinstance(stored, bytes) else stored.encode()
    if bcrypt.checkpw(pwd.encode(), hashed):
        return "Login successful!", 200

    return "Invalid credentials", 401


# ── Lab 02: Cross-Site Scripting (XSS) ──────────────────────────────────────
# Ask Copilot: "Write a Flask GET /search route that displays search results
#               for a query parameter q in an HTML response"
# Paste Copilot's code below this comment, then find and fix the vulnerability.

# YOUR CODE HERE


# ── Lab 03: Broken Authentication ────────────────────────────────────────────
# Ask Copilot: "Write a register_user(username, password) function that hashes
#               the password and stores the user in the SQLite database"
# Paste Copilot's code below this comment, then find and fix the vulnerability.

# YOUR CODE HERE


# ── Lab 04: IDOR ─────────────────────────────────────────────────────────────
# Ask Copilot: "Write a Flask GET /invoice/<invoice_id> route that returns
#               the invoice as JSON for the logged-in user"
# Paste Copilot's code below this comment, then find and fix the vulnerability.

# YOUR CODE HERE


# ── Lab 05: Sensitive Data Exposure ──────────────────────────────────────────
# Ask Copilot: "Write a Python module that connects to AWS S3 and
#               a Stripe payment API using configuration variables"
# Paste Copilot's code below this comment, then find and fix the vulnerability.

# YOUR CODE HERE


# ── Lab 06: Command Injection ────────────────────────────────────────────────
# Ask Copilot: "Write a Flask POST /ping route that pings a hostname
#               submitted by the user and returns the output"
# Paste Copilot's code below this comment, then find and fix the vulnerability.

# YOUR CODE HERE


# ── Lab 07: XXE Injection ────────────────────────────────────────────────────
# Ask Copilot: "Write a Flask POST /upload route that accepts an XML file
#               upload and returns the parsed content as JSON"
# Paste Copilot's code below this comment, then find and fix the vulnerability.

# YOUR CODE HERE


if __name__ == "__main__":
    with app.app_context():
        init_db()
    app.run(debug=False)
