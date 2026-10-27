"""Secure login must not authenticate ambiguous HTTP form credentials."""

import pytest
from werkzeug.datastructures import MultiDict


@pytest.mark.parametrize("fields", [
    [("username", "alice"), ("username", "admin"), ("password", "alice-password-1")],
    [("username", "admin"), ("username", "alice"), ("password", "alice-password-1")],
    [("username", "alice"), ("password", "alice-password-1"), ("password", "wrong")],
    [("username", "alice"), ("password", "wrong"), ("password", "alice-password-1")],
    [("username", "alice")],
    [("password", "alice-password-1")],
])
def test_ambiguous_or_missing_credentials_cannot_authenticate(client, fields):
    response = client.post("/secure/login", data=MultiDict(fields))
    assert response.status_code == 400
    assert response.headers["Cache-Control"] == "no-store"
    assert client.get("/secure/note/2").status_code == 401


def test_ambiguous_relogin_does_not_replace_existing_session(client):
    login = client.post("/secure/login", data={
        "username": "alice", "password": "alice-password-1",
    })
    assert login.status_code == 200
    ambiguous = client.post("/secure/login", data=MultiDict([
        ("username", "admin"), ("username", "alice"),
        ("password", "S3cure-Admin-Pw!"),
    ]))
    assert ambiguous.status_code == 400
    assert client.get("/secure/note/2").status_code == 200
    assert client.get("/secure/note/1").status_code == 404


def test_one_username_and_password_still_authenticate(client):
    response = client.post("/secure/login", data=MultiDict([
        ("username", "alice"), ("password", "alice-password-1"),
    ]))
    assert response.status_code == 200
    assert client.get("/secure/note/2").status_code == 200
