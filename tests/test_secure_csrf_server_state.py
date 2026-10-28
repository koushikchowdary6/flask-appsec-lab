"""Server-side CSRF nonces reject replayed signed cookies and expired forms."""

import hashlib
import re

from app import get_db


def _login_and_token(client):
    response = client.post(
        "/secure/login",
        data={"username": "alice", "password": "alice-password-1"},
    )
    assert response.status_code == 200
    form = client.get("/secure/note/2/edit")
    assert form.status_code == 200
    match = re.search(r'name="csrf_token" value="([^"]+)"', form.get_data(as_text=True))
    assert match
    return match.group(1)


def test_replaying_original_signed_cookie_cannot_reuse_consumed_token(client):
    token = _login_and_token(client)
    original_cookie = client.get_cookie("session")
    assert original_cookie is not None

    assert client.post(
        "/secure/note/2/edit",
        data={"csrf_token": token, "body": "accepted edit"},
    ).status_code == 200

    # Flask's default session is a replayable signed cookie. Restore the
    # exact cookie that carried the valid token before the successful edit.
    client.set_cookie("session", original_cookie.value)
    replay = client.post(
        "/secure/note/2/edit",
        data={"csrf_token": token, "body": "replayed edit"},
    )
    assert replay.status_code == 403
    assert client.get("/secure/note/2").get_data(as_text=True) == "accepted edit"


def test_two_clients_with_same_signed_cookie_cannot_both_consume_token(client):
    token = _login_and_token(client)
    original_cookie = client.get_cookie("session")
    assert original_cookie is not None
    with client.application.test_client() as second:
        second.set_cookie("session", original_cookie.value)
        assert client.post(
            "/secure/note/2/edit",
            data={"csrf_token": token, "body": "first write"},
        ).status_code == 200
        assert second.post(
            "/secure/note/2/edit",
            data={"csrf_token": token, "body": "second write"},
        ).status_code == 403
    assert client.get("/secure/note/2").get_data(as_text=True) == "first write"


def test_expired_nonce_is_rejected_and_get_issues_fresh_token(client):
    token = _login_and_token(client)
    old_cookie = client.get_cookie("session")
    assert old_cookie is not None
    with client.application.app_context():
        db = get_db()
        db.execute(
            "UPDATE secure_csrf_tokens SET created_at = 0 WHERE token_digest = ?",
            (hashlib.sha256(token.encode("utf-8")).hexdigest(),),
        )
        db.commit()

    assert client.post(
        "/secure/note/2/edit",
        data={"csrf_token": token, "body": "expired edit"},
    ).status_code == 403
    assert "diary" in client.get("/secure/note/2").get_data(as_text=True)
    form = client.get("/secure/note/2/edit").get_data(as_text=True)
    assert f'value="{token}"' not in form
    new_token = re.search(r'name="csrf_token" value="([^"]+)"', form).group(1)
    assert new_token != token
    assert client.post(
        "/secure/note/2/edit",
        data={"csrf_token": new_token, "body": "fresh edit"},
    ).status_code == 200


def test_invalid_body_does_not_consume_server_side_nonce(client):
    token = _login_and_token(client)
    response = client.post(
        "/secure/note/2/edit",
        data={"csrf_token": token, "body": "x" * 10_001},
    )
    assert response.status_code == 413
    assert client.post(
        "/secure/note/2/edit",
        data={"csrf_token": token, "body": "valid after rejection"},
    ).status_code == 200
