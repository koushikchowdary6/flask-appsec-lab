"""Regression tests for defense-in-depth headers on /secure routes."""


def test_secure_routes_set_browser_hardening_headers(client):
    response = client.get("/secure/search?q=hello")

    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    csp = response.headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp
    assert "object-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "form-action 'self'" in csp
    assert "base-uri 'none'" in csp


def test_vulnerable_routes_do_not_inherit_secure_blueprint_headers(client):
    response = client.get("/vuln/search?q=hello")

    # The lab intentionally keeps the vulnerable half separate so students can
    # inspect the response-level hardening difference as well as the code diff.
    assert "Content-Security-Policy" not in response.headers
    assert "X-Frame-Options" not in response.headers


def test_secure_login_and_private_notes_are_not_cached(client):
    # Both the login form and its authentication response can carry session
    # information; private notes must not persist in intermediary caches.
    for response in (
        client.get("/secure/login"),
        client.post("/secure/login", data={
            "username": "alice", "password": "alice-password-1"
        }),
        client.get("/secure/note/2"),
        client.get("/secure/note/1"),  # forbidden ownership: 404
    ):
        assert "no-store" in response.headers["Cache-Control"]


def test_public_search_and_vulnerable_demo_do_not_gain_cache_policy(client):
    assert "Cache-Control" not in client.get("/secure/search?q=hello").headers
    assert "Cache-Control" not in client.get("/vuln/login").headers
    assert "Cache-Control" not in client.get("/vuln/note/1").headers


def test_secure_form_csp_is_enforced_on_login_and_edit_errors(client):
    # Browser form-target restrictions must survive both successful forms
    # and rejected requests, not only the public search demonstration.
    for response in (
        client.get("/secure/login"),
        client.post("/secure/login", data={"username": "nobody", "password": "bad"}),
        client.get("/secure/note/2/edit"),  # unauthenticated: 401
    ):
        csp = response.headers["Content-Security-Policy"]
        assert "form-action 'self'" in csp
        assert "base-uri 'none'" in csp
        assert response.headers["X-Frame-Options"] == "DENY"
