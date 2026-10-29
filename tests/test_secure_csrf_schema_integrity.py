"""Incomplete CSRF table schemas must not survive startup silently."""

import re
import sqlite3

import pytest

import app as app_module


@pytest.mark.parametrize(
    "schema",
    [
        # A partially applied migration can have note_id but lack created_at.
        "token_digest TEXT PRIMARY KEY, user_id INTEGER NOT NULL, note_id INTEGER NOT NULL",
        # SQLite's permissive typing can hide an incorrect token owner column.
        "token_digest TEXT PRIMARY KEY, user_id TEXT NOT NULL, "
        "note_id INTEGER NOT NULL, created_at INTEGER NOT NULL",
        # A nullable owner field violates the expected token scope.
        "token_digest TEXT PRIMARY KEY, user_id INTEGER, "
        "note_id INTEGER NOT NULL, created_at INTEGER NOT NULL",
        # An unexpected required field would break token insertion.
        "token_digest TEXT PRIMARY KEY, user_id INTEGER NOT NULL, "
        "note_id INTEGER NOT NULL, created_at INTEGER NOT NULL, "
        "extra TEXT NOT NULL",
    ],
)
def test_incompatible_token_schema_is_rebuilt_before_requests(client, schema):
    with sqlite3.connect(app_module.DB_PATH) as db:
        db.execute("DROP TABLE secure_csrf_tokens")
        db.execute("CREATE TABLE secure_csrf_tokens (" + schema + ")")
        db.execute("UPDATE notes SET body = ? WHERE id = 2", ("keep my note",))
        db.commit()

    upgraded = app_module.create_app()
    upgraded.config.update(TESTING=True)

    with sqlite3.connect(app_module.DB_PATH) as db:
        columns = {
            row[1]: (row[2].upper(), row[3], row[5])
            for row in db.execute("PRAGMA table_info(secure_csrf_tokens)")
        }
        assert columns == {
            "token_digest": ("TEXT", 0, 1),
            "user_id": ("INTEGER", 1, 0),
            "note_id": ("INTEGER", 1, 0),
            "created_at": ("INTEGER", 1, 0),
        }
        assert db.execute("SELECT body FROM notes WHERE id = 2").fetchone()[0] == "keep my note"

    with upgraded.test_client() as c:
        assert c.post(
            "/secure/login",
            data={"username": "alice", "password": "alice-password-1"},
        ).status_code == 200
        form = c.get("/secure/note/2/edit")
        assert form.status_code == 200
        token = re.search(
            r'name="csrf_token" value="([^"]+)"', form.get_data(as_text=True)
        )
        assert token is not None
        assert c.post(
            "/secure/note/2/edit",
            data={"csrf_token": token.group(1), "body": "updated"},
        ).status_code == 200
        assert c.get("/secure/note/2").get_data(as_text=True) == "updated"
