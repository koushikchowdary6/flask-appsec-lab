"""Unknown users and corrupted hashes must fail closed without skipping KDF work."""

import sqlite3

import app as app_module
from app import secure


def test_unknown_username_runs_dummy_password_verification(client, monkeypatch):
    observed = []
    original = secure.check_password_hash

    def recording_check(encoded, password):
        observed.append(encoded)
        return original(encoded, password)

    monkeypatch.setattr(secure, "check_password_hash", recording_check)
    response = client.post(
        "/secure/login", data={"username": "nonexistent", "password": "wrong"}
    )
    assert response.status_code == 401
    assert observed == [secure._DUMMY_PASSWORD_HASH]


def test_existing_username_uses_its_stored_hash(client, monkeypatch):
    observed = []
    original = secure.check_password_hash

    def recording_check(encoded, password):
        observed.append(encoded)
        return original(encoded, password)

    monkeypatch.setattr(secure, "check_password_hash", recording_check)
    response = client.post(
        "/secure/login", data={"username": "alice", "password": "wrong"}
    )
    assert response.status_code == 401
    assert len(observed) == 1
    assert observed[0] != secure._DUMMY_PASSWORD_HASH


def test_malformed_stored_hash_is_rejected_without_server_error(client):
    with sqlite3.connect(app_module.DB_PATH) as conn:
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE username = ?",
            ("unknown-hash-method$bad-salt$bad-hash", "alice"),
        )
        conn.commit()

    response = client.post(
        "/secure/login",
        data={"username": "alice", "password": "alice-password-1"},
    )
    assert response.status_code == 401
    # The vulnerable teaching route still uses its own plaintext demo column.
    assert client.post(
        "/vuln/login",
        data={"username": "alice", "password": "alice-password-1"},
    ).status_code == 200
