"""Secure note edits reject HTTP parameter pollution before changing state."""

import re

import pytest
from werkzeug.datastructures import MultiDict


def _login_and_token(client):
    response = client.post(
        "/secure/login",
        data={"username": "alice", "password": "alice-password-1"},
    )
    assert response.status_code == 200
    form = client.get("/secure/note/2/edit")
    match = re.search(r'name="csrf_token" value="([^"]+)"', form.get_data(as_text=True))
    assert match
    return match.group(1)


@pytest.mark.parametrize("fields", [
    lambda token: [("csrf_token", token), ("csrf_token", "invalid"), ("body", "polluted")],
    lambda token: [("csrf_token", "invalid"), ("csrf_token", token), ("body", "polluted")],
    lambda token: [("csrf_token", token), ("body", "first"), ("body", "polluted")],
    lambda token: [("csrf_token", token), ("body", "polluted"), ("body", "first")],
    lambda token: [("csrf_token", token)],
    lambda token: [("body", "polluted")],
])
def test_duplicate_or_missing_edit_parameters_fail_closed(client, fields):
    token = _login_and_token(client)
    response = client.post(
        "/secure/note/2/edit", data=MultiDict(fields(token)),
    )
    assert response.status_code in (400, 403)
    assert "no-store" in response.headers["Cache-Control"]
    assert b"diary entry" in client.get("/secure/note/2").data


def test_one_token_and_one_body_still_allow_legitimate_empty_note(client):
    token = _login_and_token(client)
    response = client.post(
        "/secure/note/2/edit", data=MultiDict([
            ("csrf_token", token), ("body", ""),
        ]),
    )
    assert response.status_code == 200
    assert client.get("/secure/note/2").get_data(as_text=True) == ""
