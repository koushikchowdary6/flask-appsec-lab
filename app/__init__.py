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

import sqlite3
from pathlib import Path

from flask import Flask, g

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
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS notes;
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        );
        CREATE TABLE notes (
            id INTEGER PRIMARY KEY,
            owner_id INTEGER NOT NULL,
            body TEXT NOT NULL
        );
        INSERT INTO users (id, username, password) VALUES
            (1, 'admin', 'S3cure-Admin-Pw!'),
            (2, 'alice', 'alice-password-1');
        INSERT INTO notes (id, owner_id, body) VALUES
            (1, 1, 'admin note: the vault code is 4815'),
            (2, 2, 'alice note: my diary entry, private');
        """
    )
    conn.commit()
    conn.close()


def create_app() -> Flask:
    app = Flask(__name__)
    # Loaded from the environment in any real deployment; the fixed fallback
    # here exists only so the lab runs out of the box. See secure_login for
    # why a hardcoded, guessable secret ("12345" in the original) is itself a
    # finding.
    import os

    app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-only-not-for-production")

    if not DB_PATH.exists():
        init_db()

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
