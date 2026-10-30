"""Cross-site browser form submissions must not reach secure state changes.

These headers are defense in depth; clients without browser headers still need
the database-backed CSRF token for note edits.
"""

import re

import pytest


@pytest.mark.parametrize("headers", [
    {"Origin": "https://attacker.example"},
    {"Origin": "null"},
    {"Origin": "http://localhost:5000"},
    {"Origin": "http://localhost/other"},
    {"Origin": "http://localhost@attacker.example"},
    {"Origin": "http://localhost:invalid"},
    {"Sec-Fetch-Site": "cross-site"},
    {"Sec-Fetch-Site": "same-site"},
    {"Sec-Fetch-Site": "same-origin, cross-site"},
    {"Sec-Fetch-Site": "cross-site, same-origin"},
    {"Sec-Fetch-Site": "CROSS-SITE"},
    {"Sec-Fetch-Site": "unexpected"},
    {"Sec-Fetch-Site": ""},
    {"Origin": "http://localhost", "Sec-Fetch-Site": "cross-site"},
])
def test_cross_origin_secure_login_rejected_without_creating_session(client, headers):
    response = client.post(
        "/secure/login",
        data={"username": "alice", "password": "alice-password-1"},
        headers=headers,
    )
    assert response.status_code == 403
    assert response.headers["Cache-Control"] == "no-store"
    assert client.get("/secure/note/2").status_code == 401


@pytest.mark.parametrize("headers", [
    {},
    {"Origin": "http://localhost"},
    {"Origin": "http://LOCALHOST:80", "Sec-Fetch-Site": "same-origin"},
    {"Sec-Fetch-Site": "none"},
])
def test_same_origin_and_legacy_login_remain_usable(client, headers):
    response = client.post(
        "/secure/login",
        data={"username": "alice", "password": "alice-password-1"},
        headers=headers,
    )
    assert response.status_code == 200
    assert client.get("/secure/note/2").status_code == 200


@pytest.mark.parametrize("rejected_headers", [
    {"Origin": "https://attacker.example"},
    {"Sec-Fetch-Site": "same-origin, cross-site"},
    {"Sec-Fetch-Site": "unexpected"},
])
def test_cross_origin_edit_does_not_consume_valid_csrf_token(client, rejected_headers):
    assert client.post(
        "/secure/login",
        data={"username": "alice", "password": "alice-password-1"},
    ).status_code == 200
    form = client.get("/secure/note/2/edit").get_data(as_text=True)
    token = re.search(r'name="csrf_token" value="([^"]+)"', form).group(1)

    rejected = client.post(
        "/secure/note/2/edit",
        data={"csrf_token": token, "body": "cross-site overwrite"},
        headers=rejected_headers,
    )
    assert rejected.status_code == 403
    assert client.get("/secure/note/2").get_data(as_text=True) == (
        "alice note: my diary entry, private"
    )

    accepted = client.post(
        "/secure/note/2/edit",
        data={"csrf_token": token, "body": "legitimate edit"},
        headers={"Origin": "http://localhost", "Sec-Fetch-Site": "same-origin"},
    )
    assert accepted.status_code == 200
    assert client.get("/secure/note/2").get_data(as_text=True) == "legitimate edit"


def test_cross_site_metadata_does_not_block_read_only_secure_get(client):
    response = client.get(
        "/secure/search?q=hello",
        headers={"Origin": "https://attacker.example", "Sec-Fetch-Site": "cross-site"},
    )
    assert response.status_code == 200
    assert "hello" in response.get_data(as_text=True)
