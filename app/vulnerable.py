"""Deliberately vulnerable routes. Do NOT copy these into real code.

Each handler has a matching secure counterpart in app/secure.py. Read them
as a pair -- the diff between the two is the actual lesson.
"""
from __future__ import annotations

from flask import Blueprint, request, session
from markupsafe import escape

from app import get_db

bp = Blueprint("vulnerable", __name__, url_prefix="/vuln")


@bp.route("/login", methods=["GET", "POST"])
def login() -> str:
    """SQL injection: user input is concatenated straight into the query.

    Exploit: POST username = ' OR '1'='1' --  with any password logs you in
    as the first user, because the WHERE clause is always true.
    """
    if request.method == "GET":
        return _login_form("/vuln/login")

    username = request.form.get("username", "")
    password = request.form.get("password", "")
    db = get_db()

    # VULNERABLE: string interpolation builds the SQL. Never do this.
    query = (
        "SELECT id, username FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )
    row = db.execute(query).fetchone()

    if row:
        session["user_id"] = row["id"]
        session["username"] = row["username"]
        return f"Logged in as {row['username']} (id {row['id']})"
    return "Invalid credentials", 401


@bp.route("/search")
def search() -> str:
    """Reflected XSS: the query parameter is echoed into HTML unescaped.

    Exploit: /vuln/search?q=<script>alert(document.cookie)</script>
    """
    q = request.args.get("q", "")
    # VULNERABLE: q is injected into the response with no escaping.
    return f"<p>Results for: {q}</p>"


@bp.route("/note/<int:note_id>")
def note(note_id: int) -> str:
    """IDOR: any authenticated user can read any note by guessing its id.

    Exploit: log in as alice, then request /vuln/note/1 to read admin's note.
    The handler never checks that the note belongs to the caller.
    """
    if "user_id" not in session:
        return "Please log in first", 401
    db = get_db()
    # VULNERABLE: no ownership check against session["user_id"].
    row = db.execute("SELECT body FROM notes WHERE id = ?", (note_id,)).fetchone()
    if row is None:
        return "No such note", 404
    return row["body"]


@bp.route("/note/<int:note_id>/edit", methods=["GET", "POST"])
def edit_note(note_id: int):
    """CSRF demo: a logged-in user's note can be edited without a request token.

    Ownership is enforced here to isolate CSRF from the separate IDOR lesson.
    A third-party page can still induce a state-changing POST using the
    victim's existing session cookie.
    """
    if "user_id" not in session:
        return "Please log in first", 401

    db = get_db()
    owner_id = session["user_id"]
    row = db.execute(
        "SELECT body FROM notes WHERE id = ? AND owner_id = ?",
        (note_id, owner_id),
    ).fetchone()
    if row is None:
        return "No such note", 404

    if request.method == "POST":
        db.execute(
            "UPDATE notes SET body = ? WHERE id = ? AND owner_id = ?",
            (request.form.get("body", ""), note_id, owner_id),
        )
        db.commit()
        return "Note updated"

    return (
        f'<form method="post" action="/vuln/note/{note_id}/edit">'
        f'<textarea name="body">{escape(row["body"])}</textarea>'
        '<button type="submit">Save</button></form>'
    )


def _login_form(action: str) -> str:
    return (
        f'<form method="post" action="{action}">'
        'Username: <input name="username"><br>'
        'Password: <input name="password" type="password"><br>'
        '<input type="submit"></form>'
    )
