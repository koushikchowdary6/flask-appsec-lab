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


def test_vulnerable_routes_do_not_inherit_secure_blueprint_headers(client):
    response = client.get("/vuln/search?q=hello")

    # The lab intentionally keeps the vulnerable half separate so students can
    # inspect the response-level hardening difference as well as the code diff.
    assert "Content-Security-Policy" not in response.headers
    assert "X-Frame-Options" not in response.headers
