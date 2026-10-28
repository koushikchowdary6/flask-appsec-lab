"""Secure note edits reject oversized payloads without mutating the database."""

import re

from app.secure import MAX_SECURE_NOTE_BYTES, MAX_SECURE_NOTE_CHARS


def _login_and_token(client):
    response = client.post(
        "/secure/login",
        data={"username": "alice", "password": "alice-password-1"},
    )
    assert response.status_code == 200
    form = client.get("/secure/note/2/edit")
    assert form.status_code == 200
    match = re.search(r'name="csrf_token" value="([^"]+)"', form.get_data(as_text=True))
    assert match is not None
    return match.group(1)


def test_secure_note_edit_accepts_maximum_text_and_rejects_one_extra_character(client):
    token = _login_and_token(client)
    accepted = "a" * MAX_SECURE_NOTE_CHARS
    ok = client.post(
        "/secure/note/2/edit", data={"csrf_token": token, "body": accepted}
    )
    assert ok.status_code == 200

    # A successful edit consumes its CSRF token; obtain a fresh token before
    # testing the separate character-limit behavior.
    form = client.get("/secure/note/2/edit")
    match = re.search(r'name="csrf_token" value="([^"]+)"', form.get_data(as_text=True))
    assert match is not None
    fresh_token = match.group(1)
    assert fresh_token != token
    too_long = client.post(
        "/secure/note/2/edit", data={"csrf_token": fresh_token, "body": accepted + "b"}
    )
    assert too_long.status_code == 413
    assert b"Note too long" in too_long.data
    assert client.get("/secure/note/2").get_data(as_text=True) == accepted


def test_secure_note_edit_rejects_oversized_http_form_before_write(client):
    token = _login_and_token(client)
    payload = "x" * (MAX_SECURE_NOTE_BYTES + 1)
    response = client.post(
        "/secure/note/2/edit", data={"csrf_token": token, "body": payload}
    )
    assert response.status_code == 413
    assert b"diary entry" in client.get("/secure/note/2").data
    assert "no-store" in response.headers["Cache-Control"]


def test_vulnerable_teaching_route_retains_unbounded_edit_behavior(client):
    login = client.post(
        "/vuln/login", data={"username": "alice", "password": "alice-password-1"}
    )
    assert login.status_code == 200
    payload = "v" * (MAX_SECURE_NOTE_BYTES + 1)
    response = client.post("/vuln/note/2/edit", data={"body": payload})
    assert response.status_code == 200
    assert client.get("/vuln/note/2").get_data(as_text=True) == payload
