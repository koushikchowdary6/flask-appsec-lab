"""Out-of-range URL IDs must not turn secure note reads/edits into 500s.

Flask's <int:...> converter accepts Python integers larger than SQLite's
signed 64-bit bind range; sqlite3 otherwise raises OverflowError.
"""

import pytest


@pytest.mark.parametrize("note_id", [2**63, 2**64, 10**100])
@pytest.mark.parametrize("method,path_suffix", [
    ("get", ""),
    ("get", "/edit"),
    ("post", "/edit"),
])
def test_oversized_secure_note_id_returns_not_found(client, note_id, method, path_suffix):
    login = client.post(
        "/secure/login",
        data={"username": "alice", "password": "alice-password-1"},
    )
    assert login.status_code == 200

    response = getattr(client, method)(
        f"/secure/note/{note_id}{path_suffix}",
        **({"data": {"body": "should not be written"}} if method == "post" else {}),
    )
    assert response.status_code == 404
    assert "no-store" in response.headers["Cache-Control"]
    assert b"diary entry" in client.get("/secure/note/2").data


def test_maximum_signed_sqlite_id_is_valid_but_absent(client):
    login = client.post(
        "/secure/login",
        data={"username": "alice", "password": "alice-password-1"},
    )
    assert login.status_code == 200
    assert client.get(f"/secure/note/{2**63 - 1}").status_code == 404
    assert client.get(f"/secure/note/{2**63 - 1}/edit").status_code == 404
