"""Secure search rejects HTTP parameter pollution without changing the lab demo."""

import pytest


@pytest.mark.parametrize(
    "query",
    [
        "q=normal&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        "q=%3Cscript%3Ealert(1)%3C%2Fscript%3E&q=normal",
        "q=normal&q=normal",
    ],
)
def test_secure_search_rejects_duplicate_query_parameters(client, query):
    response = client.get("/secure/search?" + query)
    assert response.status_code == 400
    assert b"Ambiguous search query" in response.data
    assert b"<script>" not in response.data
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_secure_search_preserves_one_or_no_query_parameter(client):
    assert client.get("/secure/search").status_code == 200
    assert b"Results for: " in client.get("/secure/search").data
    response = client.get("/secure/search?q=%3Cb%3Etest%3C%2Fb%3E")
    assert response.status_code == 200
    assert b"&lt;b&gt;test&lt;/b&gt;" in response.data


def test_vulnerable_search_still_demonstrates_first_value_behavior(client):
    response = client.get("/vuln/search?q=first&q=second")
    assert response.status_code == 200
    assert b"first" in response.data
