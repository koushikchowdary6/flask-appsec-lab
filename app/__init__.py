"""Flask AppSec Lab.

A deliberately educational Flask app that presents common web
vulnerabilities side by side with their fixes. Every vulnerability class
has two routes: a `/vuln/...` version that is exploitable, and a
`/secure/...` version that is not. The point is to make the difference
between the two visible in the code itself, not just described in prose.

WARNING: the /vuln/* routes are intentionally insecure. Never deploy this
application anywhere reachable from an untrusted network.
"""
from __future__ import annotations

import os
import secrets
import sqlite3
from pathlib import Path

from flask import Flask, g
from werkzeug.security import generate_password_hash

DB_PATH = Path(__file__).parent / "lab.db"


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


def init_db(db_path: Path | None = None) -> None:
    """Create a fresh demo database with two users and some private notes.

    user 1 (admin)  -> note visible only to admin
    user 2 (alice)  -> a private note used to demonstrate IDOR
    """
    path = db_path or DB_PATH
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        DROP TABLE IF EXISTS secure_csrf_tokens;
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS notes;
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            password_hash TEXT
        );
        CREATE TABLE notes (
            id INTEGER PRIMARY KEY,
            owner_id INTEGER NOT NULL,
            body TEXT NOT NULL
        );
        -- Only token digests are stored; consuming a row is atomic with an edit.
        CREATE TABLE secure_csrf_tokens (
            token_digest TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            note_id INTEGER NOT NULL,
            created_at INTEGER NOT NULL
        );
        INSERT INTO users (id, username, password) VALUES
            (1, 'admin', 'S3cure-Admin-Pw!'),
            (2, 'alice', 'alice-password-1');
        INSERT INTO notes (id, owner_id, body) VALUES
            (1, 1, 'admin note: the vault code is 4815'),
            (2, 2, 'alice note: my diary entry, private');
        """
    )
    # Keep plaintext demo credentials solely for the intentionally vulnerable
    # SQL-injection route. The secure route authenticates against independently
    # salted password hashes and never compares a plaintext DB password.
    conn.executemany(
        "UPDATE users SET password_hash = ? WHERE username = ?",
        [
            (generate_password_hash("S3cure-Admin-Pw!"), "admin"),
            (generate_password_hash("alice-password-1"), "alice"),
        ],
    )
    conn.commit()
    conn.close()



def ensure_note_scoped_csrf_schema(db_path: Path) -> None:
    """Upgrade pre-note-binding demo databases without deleting users or notes.

    Older versions stored one-time CSRF token digests per user, without the
    target note. Those outstanding tokens cannot be safely migrated because
    their intended note is unknown; invalidate them during the schema change.
    """
    conn = sqlite3.connect(db_path)
    try:
        # Checking only for note_id misses partially migrated tables whose
        # missing/nullable fields break token issuance or one-time consumption.
        # The table holds only disposable token digests; recreate it if the
        # schema differs, preserving users and notes in other tables.
        expected_columns = {
            "token_digest": ("TEXT", 0, 1),
            "user_id": ("INTEGER", 1, 0),
            "note_id": ("INTEGER", 1, 0),
            "created_at": ("INTEGER", 1, 0),
        }
        columns = {
            row[1]: (row[2].upper(), row[3], row[5])
            for row in conn.execute("PRAGMA table_info(secure_csrf_tokens)")
        }
        if columns != expected_columns:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("DROP TABLE IF EXISTS secure_csrf_tokens")
            conn.execute(
                "CREATE TABLE secure_csrf_tokens ("
                "token_digest TEXT PRIMARY KEY, "
                "user_id INTEGER NOT NULL, "
                "note_id INTEGER NOT NULL, "
                "created_at INTEGER NOT NULL)"
            )
            conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def create_app() -> Flask:
    app = Flask(__name__)
    # A predictable development fallback permits anyone who knows the source
    # to forge Flask session cookies and bypass the secure note authorization.
    # Use a fresh secret per app instance unless the operator supplies one.
    # Set FLASK_SECRET_KEY to a high-entropy value when sessions must survive
    # restarts. The intentionally vulnerable routes remain local-only.
    configured_secret = os.environ.get("FLASK_SECRET_KEY")
    # A short operator-supplied key is just as forgeable as a hardcoded
    # development fallback. Reject it instead of silently weakening secure
    # session integrity. Length is a floor, not proof of randomness.
    # A 32-character secret made by repeating a tiny pattern is still easy
    # to guess and forge. This catches obvious configuration mistakes, not
    # arbitrary low-entropy passwords; use a generated random secret.
    short_period = bool(configured_secret) and any(
        len(configured_secret) % period == 0
        and configured_secret == configured_secret[:period] * (len(configured_secret) // period)
        for period in range(1, min(8, len(configured_secret)) + 1)
    )
    if configured_secret and (
        len(configured_secret) < 32 or not configured_secret.strip() or short_period
    ):
        raise ValueError(
            "FLASK_SECRET_KEY must contain at least 32 nonblank, non-periodic characters"
        )
    app.secret_key = configured_secret or secrets.token_urlsafe(32)
    # The secure Origin check compares against request.host_url. If arbitrary
    # Host headers are accepted, an attacker-controlled Host and matching
    # Origin can masquerade as same-origin. This is a localhost-only lab:
    # trust only local names, including both loopback address families.
    # Flask 3.1 validates TRUSTED_HOSTS during routing, before login handlers.
    app.config["TRUSTED_HOSTS"] = ["localhost", "127.0.0.1", "::1"]

    if not DB_PATH.exists():
        init_db()
    ensure_note_scoped_csrf_schema(DB_PATH)

    @app.teardown_appcontext
    def _close_db(exc: object) -> None:
        db = g.pop("db", None)
        if db is not None:
            db.close()

    from app.vulnerable import bp as vuln_bp
    from app.secure import bp as secure_bp

    app.register_blueprint(vuln_bp)
    app.register_blueprint(secure_bp)

    @app.route("/")
    def index() -> str:
        return (
            "<h1>Flask AppSec Lab</h1>"
            "<p>Each vulnerability has a /vuln and a /secure version. "
            "See the README for exploit walkthroughs.</p>"
            "<ul>"
            "<li>SQL injection: <code>/vuln/login</code> vs <code>/secure/login</code></li>"
            "<li>Reflected XSS: <code>/vuln/search</code> vs <code>/secure/search</code></li>"
            "<li>IDOR: <code>/vuln/note/&lt;id&gt;</code> vs <code>/secure/note/&lt;id&gt;</code></li>"
            "</ul>"
        )

    return app
