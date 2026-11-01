"""Origin normalization must not hide raw controls or malformed authorities.

urllib.parse silently strips some C0 controls; validate the raw header before
comparing parsed origins so browser CSRF checks cannot normalize bad input.
"""

import pytest

from app.secure import _parse_origin


@pytest.mark.parametrize("origin", [
    "\thttp://localhost",
    "\rhttp://localhost",
    "\nhttp://localhost",
    "\x00http://localhost",
    "http://local\thost",
    "http://local\nhost",
    "http://localhost\r",
    "http://localhost:65536",
    "http://[::1",
    "http://localhost:80/ignored",
    "http://localhost#ignored",
])
def test_actual_controls_and_malformed_origins_fail_closed(origin):
    assert _parse_origin(origin) is None


@pytest.mark.parametrize("origin, expected", [
    ("http://localhost", ("http", "localhost", 80)),
    ("http://LOCALHOST:80", ("http", "localhost", 80)),
    ("https://localhost", ("https", "localhost", 443)),
    ("http://[::1]:80", ("http", "::1", 80)),
])
def test_valid_serialized_loopback_origins_keep_effective_port(origin, expected):
    assert _parse_origin(origin) == expected
