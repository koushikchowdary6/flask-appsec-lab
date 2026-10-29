"""Future-dated server-side CSRF records must not outlive the token TTL."""

import hashlib
import re
import sqlite3
import time

import app as app_module


def _login_and_token(client):
    response = client.post(
        "/secure/login",
        data={"username": "alice", "password": "alice-password-1"},
    )
    assert response.status_code == 200
    return _form_token(client)


def _form_token(client):
    response = client.get("/secure/note/2/edit")
    assert response.status_code == 200
    match = re.search(
        r'name="csrf_token" value="([^"]+)"', response.get_data(as_text=True)
    )
    assert match is not None
    return match.group(1)


def _make_future_dated(token):
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    with sqlite3.connect(app_module.DB_PATH) as db:
        db.execute(
            "UPDATE secure_csrf_tokens SET created_at = ? WHERE token_digest = ?",
            (int(time.time()) + 2 * 24 * 60 * 60, digest),
        )
        db.commit()


def test_future_dated_nonce_cannot_authorize_edit(client):
    token = _login_and_token(client)
    _make_future_dated(token)

    rejected = client.post(
        "/secure/note/2/edit",
        data={"csrf_token": token, "body": "unauthorized future edit"},
    )
    assert rejected.status_code == 403
    assert "diary entry" in client.get("/secure/note/2").get_data(as_text=True)

    replacement = _form_token(client)
    assert replacement != token
    accepted = client.post(
        "/secure/note/2/edit",
        data={"csrf_token": replacement, "body": "authorized edit"},
    )
    assert accepted.status_code == 200
    assert client.get("/secure/note/2").get_data(as_text=True) == "authorized edit"


def test_future_dated_nonce_is_not_reused_on_form_get(client):
    token = _login_and_token(client)
    _make_future_dated(token)

    replacement = _form_token(client)
    assert replacement != token

    old_digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    with sqlite3.connect(app_module.DB_PATH) as db:
        assert db.execute(
            "SELECT 1 FROM secure_csrf_tokens WHERE token_digest = ?",
            (old_digest,),
        ).fetchone() is None
