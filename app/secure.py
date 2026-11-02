"""Secure counterparts to every route in app/vulnerable.py.

Same features, same URLs under /secure, but each vulnerability is closed.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from urllib.parse import urlsplit

from flask import Blueprint, request, session
from markupsafe import escape
from werkzeug.security import check_password_hash, generate_password_hash

from app import get_db

bp = Blueprint("secure", __name__, url_prefix="/secure")


def _parse_origin(value: str):
    """Canonicalize an HTTP Origin without accepting parser-normalized controls.

    urllib.parse strips tabs/newlines and leading C0 controls before parsing.
    HTTP Origin values must be serialized ASCII origins, not arbitrary URLs:
    reject malformed raw headers *before* urlsplit can normalize them.
    """
    if (
        not isinstance(value, str)
        or not value
        or any(not (0x21 <= ord(char) <= 0x7E) for char in value)
        or "?" in value
        or "#" in value
        or "\\" in value
    ):
        return None
    try:
        parsed = urlsplit(value)
        if parsed.netloc.endswith(":"):
            return None
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path
            or parsed.query
            or parsed.fragment
        ):
            return None
        port = parsed.port
    except ValueError:
        return None
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    return parsed.scheme, parsed.hostname.lower(), port


@bp.before_request
def reject_cross_origin_form_posts():
    """Browser defense in depth for the secure lab's state-changing forms.

    The Origin and Fetch Metadata headers help reject cross-site browser
    submissions even at the login endpoint. They are not authentication and
    cannot replace the note-edit CSRF token: non-browser clients can omit them.
    """
    if request.method != "POST":
        return None
    origin = request.headers.get("Origin")
    if origin is not None:
        expected = _parse_origin(request.host_url.rstrip("/"))
        if expected is None or _parse_origin(origin) != expected:
            return "Cross-origin secure form submission rejected", 403
    site = request.headers.get("Sec-Fetch-Site")
    # Browser Fetch Metadata has a closed vocabulary. Combined, unknown or
    # case-altered values are ambiguous and must not bypass this CSRF layer.
    if site is not None and site not in {"same-origin", "none"}:
        return "Cross-origin secure form submission rejected", 403
    return None


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
# A bounded set of per-note tokens lets users edit independent forms in
# separate browser tabs without invalidating the other note's CSRF defense.
MAX_ACTIVE_NOTE_FORMS = 16


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
    # Even the public search reflects attacker-controlled query text. It may
    # contain credentials, identifiers, or other sensitive data accidentally
    # pasted into a URL. Do not let browser or intermediary HTTP caches retain
    # any secure-route response, including search results and error pages.
    # This does not remove query strings from browser history or server logs.
    # Leave the intentionally vulnerable half unchanged for comparison.
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
        active_tokens = session.get("secure_csrf_tokens")
        expected = (active_tokens.get(str(note_id))
                    if isinstance(active_tokens, dict) else None)
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
        # Concurrent/replayed requests cannot both consume the same token.
        # Bound both ends of the validity window: a clock-skewed or corrupt
        # future timestamp must not make a token valid indefinitely.
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
        updated = db.execute(
            "UPDATE notes SET body = ? WHERE id = ? AND owner_id = ?",
            (body, note_id, owner_id),
        ).rowcount
        if updated != 1:
            # The note may have been deleted or reassigned after the earlier
            # ownership lookup. Do not report success or burn a valid CSRF
            # token unless the authorized write actually affected one row.
            # Rolling back restores the token consumed in this transaction.
            db.rollback()
            return "No such note", 404
        db.commit()
        # Only this note's form is consumed; another open note form remains
        # valid until its own one-time database nonce is used or expires.
        remaining = dict(active_tokens)
        remaining.pop(str(note_id), None)
        if remaining:
            session["secure_csrf_tokens"] = remaining
            session["secure_csrf_order"] = [
                key for key in session.get("secure_csrf_order", [])
                if key != str(note_id) and key in remaining
            ]
        else:
            session.pop("secure_csrf_tokens", None)
            session.pop("secure_csrf_order", None)
        return "Note updated"

    active_tokens = session.get("secure_csrf_tokens")
    if not isinstance(active_tokens, dict):
        active_tokens = {}
    token = active_tokens.get(str(note_id))
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
        # Flask serializes signed-cookie dictionaries with sorted keys, so
        # mapping insertion order is NOT stable across requests. Store the
        # actual issuance order as a list and evict the oldest active form.
        # Revoke the evicted nonce in SQLite too: replaying an older signed
        # cookie must not resurrect it.
        active_tokens = dict(active_tokens)
        stored_order = session.get("secure_csrf_order")
        active_order = (
            [key for key in stored_order if key in active_tokens]
            if isinstance(stored_order, list) else []
        )
        active_order.extend(key for key in active_tokens if key not in active_order)
        if len(active_tokens) >= MAX_ACTIVE_NOTE_FORMS:
            oldest_note = active_order.pop(0)
            old_token = active_tokens.pop(oldest_note)
            db.execute(
                "DELETE FROM secure_csrf_tokens WHERE token_digest = ? AND user_id = ?",
                (_csrf_digest(old_token), owner_id),
            )
        db.execute(
            "INSERT INTO secure_csrf_tokens (token_digest, user_id, note_id, created_at) "
            "VALUES (?, ?, ?, ?)",
            (_csrf_digest(token), owner_id, note_id, now),
        )
        db.commit()
        active_tokens[str(note_id)] = token
        active_order.append(str(note_id))
        session["secure_csrf_tokens"] = active_tokens
        session["secure_csrf_order"] = active_order
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
