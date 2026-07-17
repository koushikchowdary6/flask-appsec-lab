"""Prove the SQLi exists on /vuln/login and is closed on /secure/login."""


def test_vulnerable_login_is_bypassable(client):
    # Classic tautology injection; password is irrelevant.
    resp = client.post(
        "/vuln/login",
        data={"username": "' OR '1'='1' --", "password": "anything"},
    )
    assert resp.status_code == 200
    assert b"Logged in as admin" in resp.data  # first row -> admin


def test_secure_login_rejects_injection(client):
    resp = client.post(
        "/secure/login",
        data={"username": "' OR '1'='1' --", "password": "anything"},
    )
    assert resp.status_code == 401


def test_secure_login_still_works_for_real_credentials(client):
    resp = client.post(
        "/secure/login",
        data={"username": "admin", "password": "S3cure-Admin-Pw!"},
    )
    assert resp.status_code == 200
    assert b"Logged in as admin" in resp.data
