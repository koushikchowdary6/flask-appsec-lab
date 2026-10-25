"""Secure login limits unauthenticated form parsing without altering lab demos."""

from app.secure import MAX_SECURE_NOTE_BYTES


def test_secure_login_rejects_oversized_form_with_no_session(client):
    response = client.post(
        "/secure/login",
        data={"username": "x" * (MAX_SECURE_NOTE_BYTES + 1), "password": "irrelevant"},
    )
    assert response.status_code == 413
    assert response.headers["Cache-Control"] == "no-store"
    assert client.get("/secure/note/2").status_code == 401


def test_oversized_login_cannot_replace_existing_authenticated_identity(client):
    logged_in = client.post(
        "/secure/login",
        data={"username": "alice", "password": "alice-password-1"},
    )
    assert logged_in.status_code == 200

    oversized = client.post(
        "/secure/login",
        data={"username": "admin", "password": "x" * (MAX_SECURE_NOTE_BYTES + 1)},
    )
    assert oversized.status_code == 413
    # Alice still owns note 2; admin-only notes remain inaccessible.
    assert client.get("/secure/note/2").status_code == 200
    assert client.get("/secure/note/1").status_code == 404


def test_normal_secure_login_remains_usable(client):
    response = client.post(
        "/secure/login",
        data={"username": "admin", "password": "S3cure-Admin-Pw!"},
    )
    assert response.status_code == 200
    assert b"Logged in as admin" in response.data
