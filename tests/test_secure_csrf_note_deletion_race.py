"""An edit must not consume its CSRF token if the note vanishes after lookup."""

import hashlib
import re
import sqlite3

import app as app_module
from app import secure as secure_module


class _FetchedRow:
    def __init__(self, row):
        self.row = row

    def fetchone(self):
        return self.row


class _DeleteNoteAfterAuthorizationLookup:
    """Simulate another connection deleting a note after the ownership SELECT."""

    def __init__(self, connection):
        self.connection = connection
        self.did_delete = False

    def execute(self, sql, params=()):
        cursor = self.connection.execute(sql, params)
        if sql.startswith("SELECT body FROM notes") and not self.did_delete:
            # Exhaust and close the read cursor before the competing write;
            # otherwise SQLite could hold a shared read lock on this query.
            row = cursor.fetchone()
            cursor.close()
            with sqlite3.connect(app_module.DB_PATH) as competing:
                competing.execute("DELETE FROM notes WHERE id = ?", (2,))
            self.did_delete = True
            return _FetchedRow(row)
        return cursor

    def __getattr__(self, name):
        return getattr(self.connection, name)


def test_deleted_note_does_not_report_success_or_burn_csrf_token(client, monkeypatch):
    login = client.post(
        "/secure/login",
        data={"username": "alice", "password": "alice-password-1"},
    )
    assert login.status_code == 200
    form = client.get("/secure/note/2/edit")
    assert form.status_code == 200
    token = re.search(
        r'name="csrf_token" value="([^"]+)"', form.get_data(as_text=True)
    ).group(1)

    original_get_db = secure_module.get_db
    proxy = _DeleteNoteAfterAuthorizationLookup(original_get_db())
    monkeypatch.setattr(secure_module, "get_db", lambda: proxy)

    response = client.post(
        "/secure/note/2/edit",
        data={"csrf_token": token, "body": "must not be written"},
    )
    assert proxy.did_delete
    assert response.status_code == 404
    assert response.get_data(as_text=True) == "No such note"

    # The competing deletion commits, but our token DELETE is rolled back.
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    with sqlite3.connect(app_module.DB_PATH) as db:
        assert db.execute("SELECT COUNT(*) FROM notes WHERE id = 2").fetchone()[0] == 0
        assert db.execute(
            "SELECT COUNT(*) FROM secure_csrf_tokens WHERE token_digest = ?",
            (digest,),
        ).fetchone()[0] == 1
