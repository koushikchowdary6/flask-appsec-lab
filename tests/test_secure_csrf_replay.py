"""Successful secure note edits consume CSRF tokens; rejected edits do not."""

import re

from werkzeug.datastructures import MultiDict


def _token(client):
    response = client.get("/secure/note/2/edit")
    assert response.status_code == 200
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.get_data(as_text=True))
    assert match
    return match.group(1)


def _login(client):
    response = client.post(
        "/secure/login",
        data={"username": "alice", "password": "alice-password-1"},
    )
    assert response.status_code == 200


def test_successful_edit_consumes_token_and_replay_cannot_overwrite_note(client):
    _login(client)
    first_token = _token(client)
    assert client.post(
        "/secure/note/2/edit",
        data={"csrf_token": first_token, "body": "first authorized edit"},
    ).status_code == 200

    replay = client.post(
        "/secure/note/2/edit",
        data={"csrf_token": first_token, "body": "stale replay"},
    )
    assert replay.status_code == 403
    assert "no-store" in replay.headers["Cache-Control"]
    assert client.get("/secure/note/2").get_data(as_text=True) == "first authorized edit"

    second_token = _token(client)
    assert second_token != first_token
    assert client.post(
        "/secure/note/2/edit",
        data={"csrf_token": second_token, "body": "second authorized edit"},
    ).status_code == 200
    assert client.get("/secure/note/2").get_data(as_text=True) == "second authorized edit"


def test_rejected_edit_does_not_consume_valid_token(client):
    _login(client)
    token = _token(client)
    # An ambiguous request is rejected before any database write or rotation.
    response = client.post(
        "/secure/note/2/edit",
        data=MultiDict([
            ("csrf_token", token),
            ("body", "first"),
            ("body", "conflicting"),
        ]),
    )
    assert response.status_code == 400
    assert _token(client) == token
    assert client.post(
        "/secure/note/2/edit",
        data={"csrf_token": token, "body": "accepted after rejection"},
    ).status_code == 200
    assert client.get("/secure/note/2").get_data(as_text=True) == "accepted after rejection"
