"""Secure login uses salted hashes while the intentionally vulnerable route stays demonstrable."""

import sqlite3

from werkzeug.security import check_password_hash

import app as app_module


def _rows(client):
    with sqlite3.connect(app_module.DB_PATH) as conn:
        return conn.execute(
            "SELECT username, password, password_hash FROM users ORDER BY id"
        ).fetchall()


def test_demo_database_has_independently_salted_password_hashes(client):
    rows = _rows(client)
    assert [row[0] for row in rows] == ["admin", "alice"]
    for username, plaintext, encoded in rows:
        assert encoded != plaintext
        assert encoded.startswith(("scrypt:", "pbkdf2:"))
        assert check_password_hash(encoded, plaintext)
        assert not check_password_hash(encoded, "wrong-password")


def test_secure_login_ignores_plaintext_demo_password_column(client):
    with sqlite3.connect(app_module.DB_PATH) as conn:
        conn.execute("UPDATE users SET password = ? WHERE username = ?", ("altered-demo", "alice"))
        conn.commit()

    # Secure authentication follows the stored hash, not the intentionally
    # vulnerable route's plaintext demo password column.
    assert client.post(
        "/secure/login", data={"username": "alice", "password": "alice-password-1"}
    ).status_code == 200
    assert client.post(
        "/secure/login", data={"username": "alice", "password": "altered-demo"}
    ).status_code == 401
    assert client.post(
        "/vuln/login", data={"username": "alice", "password": "altered-demo"}
    ).status_code == 200


def test_secure_login_rejects_tampered_hash_even_with_correct_demo_password(client):
    with sqlite3.connect(app_module.DB_PATH) as conn:
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE username = ?",
            ("scrypt:32768:8:1$broken$broken", "alice"),
        )
        conn.commit()
    assert client.post(
        "/secure/login", data={"username": "alice", "password": "alice-password-1"}
    ).status_code == 401
    assert client.post(
        "/vuln/login", data={"username": "alice", "password": "alice-password-1"}
    ).status_code == 200
