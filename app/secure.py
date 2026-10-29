"""Secure counterparts to every route in app/vulnerable.py.

Same features, same URLs under /secure, but each vulnerability is closed.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time

from flask import Blueprint, request, session
from markupsafe import escape
from werkzeug.security import check_password_hash, generate_password_hash

from app import get_db

bp = Blueprint("secure", __name__, url_prefix="/secure")

# Limit both multipart/form payload size and stored note text on the hardened route.
# The vulnerable route is intentionally left unchanged for side-by-side study.
MAX_SECURE_NOTE_BYTES = 16_384
MAX_SECURE_NOTE_CHARS = 10_000
# Reject oversized URLs before parsing query parameters or reflecting user input.
MAX_SECURE_QUERY_BYTES = 4_096
# SQLite INTEGER primary keys are signed 64-bit values. Flask accepts larger
# Python integers in URL routes, but sqlite3 rejects binding them with OverflowError.
MAX_SQLITE_ROW_ID = (1 << 63) - 1
# Abandoned edit forms expire; the database, not a replayable signed cookie,
# determines whether a token is still valid and unused.
CSRF_TOKEN_TTL_SECONDS = 24 * 60 * 60


def _csrf_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

# Unknown accounts still exercise the password KDF, reducing the large timing
# difference between a missing username and a real user's stored hash.
# This is best-effort timing hardening, not constant-time authentication.
_DUMMY_PASSWORD_HASH = generate_password_hash(secrets.token_urlsafe(32))


@bp.after_request
def add_security_headers(response):
    """Add browser hardening to the secure half of the teaching lab.

    These headers are deliberately scoped to /secure so students can compare
    vulnerable and hardened responses as well as vulnerable and hardened code.
    """
    # Form submissions and HTML base URLs are separate CSP controls. Keep
    # a future markup-injection bug from redirecting secure login/note forms
    # to an attacker endpoint or rewriting relative URLs.
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; object-src 'none'; frame-ancestors 'none'; "
        "form-action 'self'; base-uri 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    # Login responses and authenticated note bodies can contain sensitive
    # information. Do not let browsers or shared intermediaries cache them.
    # Leave the intentionally vulnerable half unchanged for comparison.
    if request.endpoint in ("secure.login", "secure.note", "secure.edit_note"):
        response.headers["Cache-Control"] = "no-store"
    return response


@bp.route("/login", methods=["GET", "POST"])
def login() -> str:
    """Parameterized lookup plus salted password-hash verification."""
    if request.method == "GET":
        return _login_form("/secure/login")

    # Login is an unauthenticated endpoint. Bound form parsing before reading
    # attacker-controlled credentials to avoid oversized request-body work.
    # Keep the deliberately vulnerable comparison route unchanged.
    request.max_content_length = MAX_SECURE_NOTE_BYTES
    # Conflicting duplicate credential fields can be interpreted differently
    # by proxies and form parsers. Fail closed before looking up an account or
    # changing an existing authenticated session.
    usernames = request.form.getlist("username")
    passwords = request.form.getlist("password")
    if len(usernames) != 1 or len(passwords) != 1:
        return "Ambiguous or missing credentials", 400
    username, password = usernames[0], passwords[0]
    db = get_db()
    row = db.execute(
        "SELECT id, username, password_hash FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    stored_hash = row["password_hash"] if row else None
    hash_to_check = stored_hash if isinstance(stored_hash, str) and stored_hash else _DUMMY_PASSWORD_HASH
    try:
        password_ok = check_password_hash(hash_to_check, password)
    except (ValueError, TypeError):
        # A malformed stored hash must fail closed, not turn login into a 500.
        # Still perform the dummy KDF for roughly comparable work.
        check_password_hash(_DUMMY_PASSWORD_HASH, password)
        password_ok = False
    if row and stored_hash and password_ok:
        session.clear()
        session["secure_user_id"] = row["id"]
        session["secure_username"] = row["username"]
        # Database values are untrusted too: escape before interpolating into HTML.
        return f"Logged in as {escape(row['username'])} (id {row['id']})"
    return "Invalid credentials", 401


@bp.route("/search")
def search() -> str:
    """FIX for XSS: escape HTML metacharacters before reflection."""
    # Check the raw query string first: parsing attacker-sized query parameters
    # before enforcing a limit still consumes avoidable CPU and memory.
    if len(request.query_string) > MAX_SECURE_QUERY_BYTES:
        return "Search query too long", 414
    # Query parameter pollution is ambiguous across frameworks and proxies:
    # some choose the first q, others the last. Reject duplicates before
    # reflecting a value, even if both supplied values are identical.
    queries = request.args.getlist("q")
    if len(queries) > 1:
        return "Ambiguous search query", 400
    q = queries[0] if queries else ""
    return f"<p>Results for: {escape(q)}</p>"


@bp.route("/note/<int:note_id>")
def note(note_id: int) -> str:
    """FIX for IDOR: scope the query to the caller's own user id."""
    if "secure_user_id" not in session:
        return "Please log in first", 401
    if note_id > MAX_SQLITE_ROW_ID:
        return "No such note", 404
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


@bp.route("/note/<int:note_id>/edit", methods=["GET", "POST"])
def edit_note(note_id: int):
    """Authenticate, authorize, then consume a database-backed CSRF token.

    The browser cookie binds the form token to the session; SQLite records
    whether that token is unused. An old signed cookie cannot restore a token
    already consumed by a successful edit.
    """
    if request.method == "POST":
        # Werkzeug checks this limit while parsing request.form, before the
        # attacker-controlled body can be buffered in full.
        request.max_content_length = MAX_SECURE_NOTE_BYTES

    if "secure_user_id" not in session:
        return "Please log in first", 401
    if note_id > MAX_SQLITE_ROW_ID:
        return "No such note", 404

    db = get_db()
    owner_id = session["secure_user_id"]
    row = db.execute(
        "SELECT body FROM notes WHERE id = ? AND owner_id = ?",
        (note_id, owner_id),
    ).fetchone()
    if row is None:
        return "No such note", 404

    if request.method == "POST":
        # HTTP parameter pollution can supply conflicting token/body values.
        # Accept exactly one of each instead of silently choosing the first
        # value, which different form parsers or middleware may interpret
        # differently. Do not mutate the note on ambiguous requests.
        tokens = request.form.getlist("csrf_token")
        bodies = request.form.getlist("body")
        if len(tokens) != 1:
            return "Invalid CSRF token", 403
        if len(bodies) != 1:
            return "Ambiguous or missing note body", 400
        expected = session.get("secure_csrf_token")
        supplied = tokens[0]
        if (
            not isinstance(expected, str)
            or not isinstance(supplied, str)
            or not hmac.compare_digest(expected, supplied)
        ):
            return "Invalid CSRF token", 403
        body = bodies[0]
        if len(body) > MAX_SECURE_NOTE_CHARS:
            return "Note too long", 413
        # DELETE and UPDATE share one SQLite transaction. Bind the nonce to
        # the intended note as well as the user: a valid form for note A must
        # never authorize an edit to another note owned by the same user.
        # Concurrent/replayed requests cannot both consume the same token.\n        # Bound both ends of the validity window: a clock-skewed or corrupt\n        # future timestamp must not make a token valid indefinitely.
        now = int(time.time())
        consumed = db.execute(
            "DELETE FROM secure_csrf_tokens "
            "WHERE token_digest = ? AND user_id = ? AND note_id = ? "
            "AND created_at BETWEEN ? AND ?",
            (_csrf_digest(supplied), owner_id, note_id, now - CSRF_TOKEN_TTL_SECONDS, now),
        ).rowcount
        if consumed != 1:
            db.rollback()
            return "Invalid CSRF token", 403
        db.execute(
            "UPDATE notes SET body = ? WHERE id = ? AND owner_id = ?",
            (body, note_id, owner_id),
        )
        db.commit()
        session.pop("secure_csrf_token", None)
        return "Note updated"

    token = session.get("secure_csrf_token")
    now = int(time.time())
    valid = (
        isinstance(token, str)
        and db.execute(
            "SELECT 1 FROM secure_csrf_tokens "
            "WHERE token_digest = ? AND user_id = ? AND note_id = ? "
            "AND created_at BETWEEN ? AND ?",
            (_csrf_digest(token), owner_id, note_id, now - CSRF_TOKEN_TTL_SECONDS, now),
        ).fetchone() is not None
    )
    if not valid:
        token = secrets.token_urlsafe(32)
        db.execute(
            "DELETE FROM secure_csrf_tokens WHERE created_at < ? OR created_at > ?",
            (now - CSRF_TOKEN_TTL_SECONDS, now),
        )
        db.execute(
            "INSERT INTO secure_csrf_tokens (token_digest, user_id, note_id, created_at) "
            "VALUES (?, ?, ?, ?)",
            (_csrf_digest(token), owner_id, note_id, now),
        )
        db.commit()
        session["secure_csrf_token"] = token
    return (
        f'<form method="post" action="/secure/note/{note_id}/edit">'
        f'<input type="hidden" name="csrf_token" value="{escape(token)}">'
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
