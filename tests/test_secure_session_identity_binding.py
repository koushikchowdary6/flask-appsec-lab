"""A signed cookie must not authorize notes after account identity changes."""

import sqlite3

import pytest

import app as app_module


def _login(client):
    response = client.post(
        "/secure/login",
        data={"username": "alice", "password": "alice-password-1"},
    )
    assert response.status_code == 200


@pytest.mark.parametrize("mutation", ["delete", "rename", "replace"])
def test_stale_account_cookie_cannot_read_or_edit_notes(client, mutation):
    _login(client)
    assert client.get("/secure/note/2").status_code == 200
    assert client.get("/secure/note/2/edit").status_code == 200

    with sqlite3.connect(app_module.DB_PATH) as db:
        if mutation == "delete":
            db.execute("DELETE FROM users WHERE id = 2")
        elif mutation == "rename":
            db.execute("UPDATE users SET username = 'new-alice' WHERE id = 2")
        else:
            db.execute("DELETE FROM users WHERE id = 2")
            db.execute(
                "INSERT INTO users (id, username, password, password_hash) "
                "VALUES (2, 'new-owner', 'unrelated', 'unrelated')"
            )

    for path in ("/secure/note/2", "/secure/note/2/edit"):
        assert client.get(path).status_code == 401
    assert client.post(
        "/secure/note/2/edit", data={"body": "must not be written"}
    ).status_code == 401
    with sqlite3.connect(app_module.DB_PATH) as db:
        body = db.execute("SELECT body FROM notes WHERE id = 2").fetchone()[0]
    assert body == "alice note: my diary entry, private"


@pytest.mark.parametrize("bad_id", ["2", True, -1, 2**80])
def test_malformed_session_user_ids_fail_closed(client, bad_id):
    _login(client)
    with client.session_transaction() as session:
        session["secure_user_id"] = bad_id
    assert client.get("/secure/note/2").status_code == 401
    assert client.get("/secure/note/2/edit").status_code == 401
    assert client.post(
        "/secure/note/2/edit", data={"body": "bad identity"}
    ).status_code == 401


def test_missing_username_binding_cannot_authorize_note(client):
    _login(client)
    with client.session_transaction() as session:
        session.pop("secure_username")
    assert client.get("/secure/note/2").status_code == 401
    assert client.get("/secure/note/2/edit").status_code == 401
