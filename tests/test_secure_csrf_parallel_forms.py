"""Independent note-edit tabs retain one-time CSRF safety with bounded cookies."""

import hashlib
import re
import sqlite3

import app as app_module
from app.secure import MAX_ACTIVE_NOTE_FORMS


def _login(client):
    response = client.post(
        "/secure/login",
        data={"username": "alice", "password": "alice-password-1"},
    )
    assert response.status_code == 200


def _form_token(client, note_id):
    response = client.get(f"/secure/note/{note_id}/edit")
    assert response.status_code == 200
    match = re.search(
        r'name="csrf_token" value="([^"]+)"', response.get_data(as_text=True)
    )
    assert match is not None
    return match.group(1)


def _add_notes(ids):
    with sqlite3.connect(app_module.DB_PATH) as db:
        db.executemany(
            "INSERT INTO notes (id, owner_id, body) VALUES (?, 2, ?)",
            [(note_id, f"original note {note_id}") for note_id in ids],
        )


def test_independent_note_forms_can_be_submitted_in_either_order(client):
    _add_notes([3])
    _login(client)
    first = _form_token(client, 2)
    second = _form_token(client, 3)
    assert first != second

    assert client.post(
        "/secure/note/2/edit",
        data={"csrf_token": first, "body": "edited two"},
    ).status_code == 200
    assert client.post(
        "/secure/note/3/edit",
        data={"csrf_token": second, "body": "edited three"},
    ).status_code == 200

    assert client.get("/secure/note/2").get_data(as_text=True) == "edited two"
    assert client.get("/secure/note/3").get_data(as_text=True) == "edited three"
    for note_id, token in [(2, first), (3, second)]:
        assert client.post(
            f"/secure/note/{note_id}/edit",
            data={"csrf_token": token, "body": "replay"},
        ).status_code == 403


def test_form_for_other_note_cannot_use_an_independent_token(client):
    _add_notes([3])
    _login(client)
    first = _form_token(client, 2)
    second = _form_token(client, 3)

    assert client.post(
        "/secure/note/3/edit",
        data={"csrf_token": first, "body": "cross-note"},
    ).status_code == 403
    assert client.post(
        "/secure/note/2/edit",
        data={"csrf_token": second, "body": "cross-note"},
    ).status_code == 403
    assert client.post(
        "/secure/note/2/edit",
        data={"csrf_token": first, "body": "legitimate"},
    ).status_code == 200


def test_oldest_form_is_revoked_when_session_cookie_map_reaches_limit(client):
    _add_notes(range(3, MAX_ACTIVE_NOTE_FORMS + 3))
    _login(client)
    oldest = _form_token(client, 2)
    oldest_cookie = client.get_cookie("session")
    assert oldest_cookie is not None

    # Opening one more form than the limit evicts only the oldest note token.
    newer = {}
    for note_id in range(3, MAX_ACTIVE_NOTE_FORMS + 3):
        newer[note_id] = _form_token(client, note_id)

    with sqlite3.connect(app_module.DB_PATH) as db:
        assert db.execute(
            "SELECT COUNT(*) FROM secure_csrf_tokens"
        ).fetchone()[0] == MAX_ACTIVE_NOTE_FORMS
        assert db.execute(
            "SELECT COUNT(*) FROM secure_csrf_tokens WHERE token_digest = ?",
            (hashlib.sha256(oldest.encode()).hexdigest(),),
        ).fetchone()[0] == 0

    # Even a restored signed cookie cannot resurrect an evicted database nonce.
    client.set_cookie("session", oldest_cookie.value)
    assert client.post(
        "/secure/note/2/edit",
        data={"csrf_token": oldest, "body": "evicted replay"},
    ).status_code == 403
    assert client.get("/secure/note/2").get_data(as_text=True).startswith("alice note")
