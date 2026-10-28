"""Secure CSRF nonces authorize only the note whose form issued them."""

import hashlib
import re
import sqlite3

import app as app_module


def _setup_two_alice_notes(client):
    with sqlite3.connect(app_module.DB_PATH) as db:
        db.execute(
            "INSERT INTO notes (id, owner_id, body) VALUES (?, ?, ?)",
            (3, 2, "alice second private note"),
        )
        db.commit()
    response = client.post(
        "/secure/login",
        data={"username": "alice", "password": "alice-password-1"},
    )
    assert response.status_code == 200


def _token(client, note_id):
    response = client.get(f"/secure/note/{note_id}/edit")
    assert response.status_code == 200
    match = re.search(
        r'name="csrf_token" value="([^"]+)"', response.get_data(as_text=True)
    )
    assert match is not None
    return match.group(1)


def test_form_for_one_owned_note_cannot_edit_another_owned_note(client):
    _setup_two_alice_notes(client)
    token = _token(client, 2)

    wrong_target = client.post(
        "/secure/note/3/edit",
        data={"csrf_token": token, "body": "unauthorized cross-note edit"},
    )
    assert wrong_target.status_code == 403
    assert client.get("/secure/note/3").get_data(as_text=True) == (
        "alice second private note"
    )

    # A failed cross-target attempt must not consume the legitimate token.
    assert client.post(
        "/secure/note/2/edit",
        data={"csrf_token": token, "body": "valid note two edit"},
    ).status_code == 200
    assert client.get("/secure/note/2").get_data(as_text=True) == (
        "valid note two edit"
    )


def test_switching_note_forms_rotates_session_token_and_binds_db_record(client):
    _setup_two_alice_notes(client)
    first = _token(client, 2)
    second = _token(client, 3)
    assert second != first

    with sqlite3.connect(app_module.DB_PATH) as db:
        rows = db.execute(
            "SELECT note_id FROM secure_csrf_tokens WHERE token_digest IN (?, ?)",
            (
                hashlib.sha256(first.encode()).hexdigest(),
                hashlib.sha256(second.encode()).hexdigest(),
            ),
        ).fetchall()
    assert sorted(row[0] for row in rows) == [2, 3]

    assert client.post(
        "/secure/note/2/edit",
        data={"csrf_token": second, "body": "wrong target"},
    ).status_code == 403
    assert client.post(
        "/secure/note/3/edit",
        data={"csrf_token": second, "body": "valid note three edit"},
    ).status_code == 200
    assert client.get("/secure/note/3").get_data(as_text=True) == (
        "valid note three edit"
    )
