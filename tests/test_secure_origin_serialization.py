"""HTTP Origin must be validated before urllib normalizes malformed input."""

import pytest

from app.secure import _parse_origin


@pytest.mark.parametrize("origin", [
    " http://localhost",
    "\\thttp://localhost",
    "http://local\\nhost",
    "http://localhost\\r",
    "\\x00http://localhost",
    "http://localhost?",
    "http://localhost#",
    "http://localhost:",
    "http://localhost\\\\",
    "http://locálhost",
])
def test_noncanonical_raw_origins_rejected(origin):
    assert _parse_origin(origin) is None


@pytest.mark.parametrize("origin", [
    "http://localhost?",
    "http://localhost#",
    "http://localhost:",
    "http://localhost\\\\",
])
def test_malformed_origin_cannot_create_secure_login_session(client, origin):
    response = client.post(
        "/secure/login",
        data={"username": "alice", "password": "alice-password-1"},
        headers={"Origin": origin},
    )
    assert response.status_code == 403
    assert client.get("/secure/note/2").status_code == 401


@pytest.mark.parametrize("origin", [
    "http://localhost",
    "http://LOCALHOST:80",
])
def test_valid_serialized_origins_still_allow_login(client, origin):
    response = client.post(
        "/secure/login",
        data={"username": "alice", "password": "alice-password-1"},
        headers={"Origin": origin},
    )
    assert response.status_code == 200
    assert client.get("/secure/note/2").status_code == 200
