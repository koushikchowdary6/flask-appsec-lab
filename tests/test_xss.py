"""Prove reflected XSS on /vuln/search and its absence on /secure/search."""

PAYLOAD = "<script>alert(1)</script>"


def test_vulnerable_search_reflects_raw_script(client):
    resp = client.get("/vuln/search", query_string={"q": PAYLOAD})
    assert PAYLOAD.encode() in resp.data  # raw <script> reaches the browser


def test_secure_search_escapes_script(client):
    resp = client.get("/secure/search", query_string={"q": PAYLOAD})
    assert PAYLOAD.encode() not in resp.data
    assert b"&lt;script&gt;" in resp.data  # rendered inert
