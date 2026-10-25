"""Prove reflected XSS and stored-markup escaping on secure routes."""

import sqlite3

import app as app_module

PAYLOAD = "<script>alert(1)</script>"


def test_vulnerable_search_reflects_raw_script(client):
    resp = client.get("/vuln/search", query_string={"q": PAYLOAD})
    assert PAYLOAD.encode() in resp.data  # raw <script> reaches the browser


def test_secure_search_escapes_script(client):
    resp = client.get("/secure/search", query_string={"q": PAYLOAD})
    assert PAYLOAD.encode() not in resp.data
    assert b"&lt;script&gt;" in resp.data  # rendered inert



def test_stored_markup_is_raw_on_vulnerable_route_but_escaped_on_secure_route(client):
    stored_markup = "<strong>stored markup</strong>"
    with sqlite3.connect(app_module.DB_PATH) as db:
        db.execute(
            "INSERT INTO notes (id, owner_id, body) VALUES (?, ?, ?)",
            (99, 1, stored_markup),
        )
        db.commit()

    vulnerable_login = client.post(
        "/vuln/login",
        data={"username": "admin", "password": "S3cure-Admin-Pw!"},
    )
    assert vulnerable_login.status_code == 200
    vulnerable = client.get("/vuln/note/99")
    assert stored_markup.encode() in vulnerable.data

    secure_login = client.post(
        "/secure/login",
        data={"username": "admin", "password": "S3cure-Admin-Pw!"},
    )
    assert secure_login.status_code == 200
    secure = client.get("/secure/note/99")
    assert secure.status_code == 200
    assert stored_markup.encode() not in secure.data
    assert b"&lt;strong&gt;stored markup&lt;/strong&gt;" in secure.data


def test_secure_search_bounds_raw_query_bytes_but_preserves_normal_requests(client):
    # A URL-length guard must reject the raw bytes before Werkzeug parses
    # attacker-controlled parameters. Keep the teaching route unchanged.
    accepted = client.get("/secure/search", query_string={"q": "x" * 4000})
    assert accepted.status_code == 200
    assert b"x" * 4000 in accepted.data

    oversized = client.get("/secure/search", query_string={"q": "x" * 4096})
    assert oversized.status_code == 414
    assert b"x" * 4096 not in oversized.data
    assert oversized.headers["X-Content-Type-Options"] == "nosniff"

    vulnerable = client.get("/vuln/search", query_string={"q": "x" * 4096})
    assert vulnerable.status_code == 200
    assert b"x" * 4096 in vulnerable.data


def test_secure_search_limits_encoded_bytes_not_decoded_characters(client):
    # A small number of percent-encoded Unicode characters can consume a
    # large request target; the limit applies to the wire representation.
    response = client.get("/secure/search", query_string={"q": "\U0001f600" * 350})
    assert response.status_code == 414
