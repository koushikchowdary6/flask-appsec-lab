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
