"""Prove IDOR on /vuln/note and its absence on /secure/note."""


def _login(client, prefix, username, password):
    return client.post(
        f"{prefix}/login", data={"username": username, "password": password}
    )


def test_vulnerable_note_allows_cross_user_read(client):
    # Log in as alice (id 2), then read admin's note (id 1).
    _login(client, "/vuln", "alice", "alice-password-1")
    resp = client.get("/vuln/note/1")
    assert resp.status_code == 200
    assert b"vault code" in resp.data  # alice read admin's secret


def test_secure_note_blocks_cross_user_read(client):
    _login(client, "/secure", "alice", "alice-password-1")
    resp = client.get("/secure/note/1")
    assert resp.status_code == 404  # can't reach a note she doesn't own


def test_secure_note_allows_own_read(client):
    _login(client, "/secure", "alice", "alice-password-1")
    resp = client.get("/secure/note/2")
    assert resp.status_code == 200
    assert b"diary" in resp.data
