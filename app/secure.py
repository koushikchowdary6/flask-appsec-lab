"""Secure counterparts to every route in app/vulnerable.py.

Same features, same URLs under /secure, but each vulnerability is closed.
"""
from __future__ import annotations

from flask import Blueprint, request, session
from markupsafe import escape

from app import get_db

bp = Blueprint("secure", __name__, url_prefix="/secure")


@bp.after_request
def add_security_headers(response):
    """Add browser hardening to the secure half of the teaching lab.

    These headers are deliberately scoped to /secure so students can compare
    vulnerable and hardened responses as well as vulnerable and hardened code.
    """
    response.headers["Content-Security-Policy"] = "default-src 'self'; object-src 'none'; frame-ancestors 'none'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    # Login responses and authenticated note bodies can contain sensitive
    # information. Do not let browsers or shared intermediaries cache them.
    # Leave the intentionally vulnerable half unchanged for comparison.
    if request.endpoint in ("secure.login", "secure.note"):
        response.headers["Cache-Control"] = "no-store"
    return response


@bp.route("/login", methods=["GET", "POST"])
def login() -> str:
    """FIX for SQLi: parameterized query. User input is bound, never concatenated."""
    if request.method == "GET":
        return _login_form("/secure/login")

    username = request.form.get("username", "")
    password = request.form.get("password", "")
    db = get_db()
    row = db.execute(
        "SELECT id, username FROM users WHERE username = ? AND password = ?",
        (username, password),
    ).fetchone()
    if row:
        session.clear()
        session["secure_user_id"] = row["id"]
        session["secure_username"] = row["username"]
        # Database values are untrusted too: escape before interpolating into HTML.
        return f"Logged in as {escape(row['username'])} (id {row['id']})"
    return "Invalid credentials", 401


@bp.route("/search")
def search() -> str:
    """FIX for XSS: escape HTML metacharacters before reflection."""
    q = request.args.get("q", "")
    return f"<p>Results for: {escape(q)}</p>"


@bp.route("/note/<int:note_id>")
def note(note_id: int) -> str:
    """FIX for IDOR: scope the query to the caller's own user id."""
    if "secure_user_id" not in session:
        return "Please log in first", 401
    db = get_db()
    row = db.execute(
        "SELECT body FROM notes WHERE id = ? AND owner_id = ?",
        (note_id, session["secure_user_id"]),
    ).fetchone()
    if row is None:
        return "No such note", 404
    # Note bodies are data, not markup. Escaping here prevents stored content
    # from becoming executable HTML if note creation is added to the lab later.
    return str(escape(row["body"]))


def _login_form(action: str) -> str:
    return (
        f'<form method="post" action="{action}">'
        'Username: <input name="username"><br>'
        'Password: <input name="password" type="password"><br>'
        '<input type="submit"></form>'
    )
