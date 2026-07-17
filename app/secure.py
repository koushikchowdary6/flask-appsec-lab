"""Secure counterparts to every route in app/vulnerable.py.

Same features, same URLs under /secure, but each vulnerability is closed.
"""
from __future__ import annotations

from flask import Blueprint, request, session
from markupsafe import escape

from app import get_db

bp = Blueprint("secure", __name__, url_prefix="/secure")


@bp.route("/login", methods=["GET", "POST"])
def login() -> str:
    """FIX for SQLi: parameterized query. User input is bound, never
    concatenated, so ' OR '1'='1' is treated as a literal username."""
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
        session.clear()  # avoid session fixation: new session on privilege change
        session["user_id"] = row["id"]
        session["username"] = row["username"]
        return f"Logged in as {row['username']} (id {row['id']})"
    return "Invalid credentials", 401


@bp.route("/search")
def search() -> str:
    """FIX for XSS: escape() neutralizes HTML metacharacters before they
    reach the response, so injected <script> renders as inert text."""
    q = request.args.get("q", "")
    return f"<p>Results for: {escape(q)}</p>"


@bp.route("/note/<int:note_id>")
def note(note_id: int) -> str:
    """FIX for IDOR: the query is scoped to the caller's own user id, so a
    note belonging to someone else simply isn't found."""
    if "user_id" not in session:
        return "Please log in first", 401
    db = get_db()
    row = db.execute(
        "SELECT body FROM notes WHERE id = ? AND owner_id = ?",
        (note_id, session["user_id"]),
    ).fetchone()
    if row is None:
        # Same response whether the note doesn't exist or isn't yours --
        # don't leak which notes exist.
        return "No such note", 404
    return row["body"]


def _login_form(action: str) -> str:
    return (
        f'<form method="post" action="{action}">'
        'Username: <input name="username"><br>'
        'Password: <input name="password" type="password"><br>'
        '<input type="submit"></form>'
    )
