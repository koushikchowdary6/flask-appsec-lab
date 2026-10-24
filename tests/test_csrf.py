"""Paired CSRF regression tests: forged edits work only on the teaching route."""

import re


def _login(client, prefix="/secure", username="alice", password="alice-password-1"):
    response = client.post(
        f"{prefix}/login", data={"username": username, "password": password}
    )
    assert response.status_code == 200


def _token(client, note_id=2):
    response = client.get(f"/secure/note/{note_id}/edit")
    assert response.status_code == 200
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.get_data(as_text=True))
    assert match, "secure edit form must carry a CSRF token"
    return match.group(1)


def test_forged_edit_succeeds_only_on_vulnerable_route(client):
    _login(client, "/vuln")
    response = client.post("/vuln/note/2/edit", data={"body": "forged edit"})
    assert response.status_code == 200
    assert b"forged edit" in client.get("/vuln/note/2").data

    _login(client, "/secure")
    response = client.post("/secure/note/2/edit", data={"body": "another forged edit"})
    assert response.status_code == 403
    assert b"forged edit" in client.get("/secure/note/2").data
    assert b"another forged edit" not in client.get("/secure/note/2").data


def test_legitimate_secure_form_update_works_and_is_not_cached(client):
    _login(client)
    token = _token(client)
    response = client.post(
        "/secure/note/2/edit", data={"body": "authorized edit", "csrf_token": token}
    )
    assert response.status_code == 200
    assert b"authorized edit" in client.get("/secure/note/2").data
    assert "no-store" in response.headers["Cache-Control"]
    assert "no-store" in client.get("/secure/note/2/edit").headers["Cache-Control"]


def test_missing_and_invalid_tokens_do_not_modify_note(client):
    _login(client)
    token = _token(client)
    for supplied in ({}, {"csrf_token": "not-the-token"}):
        response = client.post(
            "/secure/note/2/edit", data={"body": "unauthorized", **supplied}
        )
        assert response.status_code == 403
    assert b"diary" in client.get("/secure/note/2").data
    assert b"unauthorized" not in client.get("/secure/note/2").data
    assert len(token) >= 32


def test_secure_csrf_token_is_bound_to_session(client):
    _login(client)
    token = _token(client)
    with client.application.test_client() as other:
        _login(other)
        response = other.post(
            "/secure/note/2/edit",
            data={"body": "cross-session", "csrf_token": token},
        )
        assert response.status_code == 403
    assert b"diary" in client.get("/secure/note/2").data


def test_relogin_invalidates_previous_csrf_token(client):
    _login(client)
    old_token = _token(client)
    _login(client)  # secure login clears the session before reauthenticating
    new_token = _token(client)
    assert new_token != old_token
    response = client.post(
        "/secure/note/2/edit",
        data={"body": "stale token", "csrf_token": old_token},
    )
    assert response.status_code == 403
    assert b"diary" in client.get("/secure/note/2").data


def test_note_edit_enforces_ownership_on_both_routes(client):
    _login(client, "/vuln")
    assert client.get("/vuln/note/1/edit").status_code == 404
    assert client.post("/vuln/note/1/edit", data={"body": "nope"}).status_code == 404
    _login(client, "/secure")
    assert client.get("/secure/note/1/edit").status_code == 404
    assert client.post("/secure/note/1/edit", data={"body": "nope"}).status_code == 404


def test_edit_requires_authentication_and_escapes_existing_note_text(client):
    for prefix in ("/vuln", "/secure"):
        assert client.get(f"{prefix}/note/2/edit").status_code == 401
        assert client.post(f"{prefix}/note/2/edit", data={"body": "no"}).status_code == 401
    _login(client)
    token = _token(client)
    payload = "<script>alert(1)</script>"
    assert client.post(
        "/secure/note/2/edit", data={"body": payload, "csrf_token": token}
    ).status_code == 200
    html = client.get("/secure/note/2/edit").get_data(as_text=True)
    assert payload not in html
    assert "&lt;script&gt;" in html
