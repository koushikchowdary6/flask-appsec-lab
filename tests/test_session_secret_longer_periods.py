"""Operator-provided signing keys must not pass length checks by repetition."""

import pytest

from app import create_app


@pytest.mark.parametrize("period", [
    "aB3!cD4@eF5#gH6$",  # 16 chars repeated to 32
    "abC123!@#",         # 9 chars repeated to 36
    "Abc123!@def456#$Ghi789%^jkl012&*",  # 32 chars repeated to 64
])
def test_longer_repeating_secret_is_rejected(monkeypatch, period):
    monkeypatch.setenv("FLASK_SECRET_KEY", period * 2)
    with pytest.raises(ValueError, match="FLASK_SECRET_KEY"):
        create_app()


def test_nonrepeating_32_character_secret_is_accepted(monkeypatch):
    secret = "aB3!cD4@eF5#gH6$iJ7%kL8^mN9&pQ0*"
    assert len(secret) == 32
    monkeypatch.setenv("FLASK_SECRET_KEY", secret)
    assert create_app().secret_key == secret
