"""Legacy local demo databases upgrade CSRF storage without losing notes."""

import re
import sqlite3

import app as app_module


def test_legacy_csrf_table_upgrades_and_invalidates_old_tokens(client):
    # Simulate a database created before CSRF tokens were bound to note IDs.
    with sqlite3.connect(app_module.DB_PATH) as db:
        db.execute("DROP TABLE secure_csrf_tokens")
        db.execute(
            "CREATE TABLE secure_csrf_tokens ("
            "token_digest TEXT PRIMARY KEY, "
            "user_id INTEGER NOT NULL, "
            "created_at INTEGER NOT NULL)"
        )
        db.execute(
            "INSERT INTO secure_csrf_tokens VALUES (?, ?, ?)",
            ("legacy-token-digest", 2, 100),
        )
        db.execute(
            "UPDATE notes SET body = ? WHERE id = 2",
            ("preserved existing note",),
        )
        db.commit()

    upgraded = app_module.create_app()
    upgraded.config.update(TESTING=True)

    with sqlite3.connect(app_module.DB_PATH) as db:
        columns = {row[1] for row in db.execute("PRAGMA table_info(secure_csrf_tokens)")}
        assert "note_id" in columns
        assert db.execute("SELECT COUNT(*) FROM secure_csrf_tokens").fetchone()[0] == 0
        assert db.execute("SELECT body FROM notes WHERE id = 2").fetchone()[0] == (
            "preserved existing note"
        )

    with upgraded.test_client() as c:
        assert c.post(
            "/secure/login",
            data={"username": "alice", "password": "alice-password-1"},
        ).status_code == 200
        form = c.get("/secure/note/2/edit")
        assert form.status_code == 200
        assert re.search(r'name="csrf_token" value="[^"]+"', form.get_data(as_text=True))
        assert c.get("/secure/note/2").get_data(as_text=True) == (
            "preserved existing note"
        )


def test_existing_note_scoped_tokens_survive_app_reinitialization(client):
    assert client.post(
        "/secure/login",
        data={"username": "alice", "password": "alice-password-1"},
    ).status_code == 200
    assert client.get("/secure/note/2/edit").status_code == 200

    with sqlite3.connect(app_module.DB_PATH) as db:
        before = db.execute(
            "SELECT token_digest, user_id, note_id, created_at FROM secure_csrf_tokens"
        ).fetchall()
    assert len(before) == 1

    app_module.create_app()

    with sqlite3.connect(app_module.DB_PATH) as db:
        after = db.execute(
            "SELECT token_digest, user_id, note_id, created_at FROM secure_csrf_tokens"
        ).fetchall()
    assert after == before
