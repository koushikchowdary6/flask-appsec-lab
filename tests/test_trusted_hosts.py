"""Host-header trust is required before Origin-based secure form checks.

An attacker-supplied Host must not redefine what the app considers
"same origin" by pairing it with an equally attacker-controlled Origin.
The deliberately vulnerable routes are local-only as well.
"""

import pytest


@pytest.mark.parametrize("host", [
    "attacker.example",
    "localhost.attacker.example",
    "127.0.0.1.attacker.example",
])
def test_matching_attacker_host_and_origin_cannot_authenticate(client, host):
    response = client.post(
        "/secure/login",
        base_url=f"http://{host}",
        headers={"Origin": f"http://{host}"},
        data={"username": "alice", "password": "alice-password-1"},
    )
    assert response.status_code == 400
    assert client.get("/secure/note/2").status_code == 401


def test_trusted_loopback_host_with_explicit_port_remains_usable(client):
    base = "http://127.0.0.1:5000"
    response = client.post(
        "/secure/login",
        base_url=base,
        headers={"Origin": base},
        data={"username": "alice", "password": "alice-password-1"},
    )
    assert response.status_code == 200
    assert client.get("/secure/note/2", base_url=base).status_code == 200


def test_localhost_default_remains_usable(client):
    response = client.post(
        "/secure/login",
        headers={"Origin": "http://localhost"},
        data={"username": "alice", "password": "alice-password-1"},
    )
    assert response.status_code == 200


def test_intentionally_vulnerable_routes_are_not_exposed_on_foreign_hosts(client):
    response = client.get(
        "/vuln/search?q=hello", base_url="http://attacker.example",
    )
    assert response.status_code == 400
