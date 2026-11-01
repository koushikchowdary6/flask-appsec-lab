"""A known source-code fallback must not let attackers forge secure sessions."""

from app import create_app


def test_default_secret_is_unpredictable_per_app_instance(monkeypatch, client):
    monkeypatch.delenv("FLASK_SECRET_KEY", raising=False)
    first = create_app()
    second = create_app()

    assert first.secret_key != second.secret_key
    assert first.secret_key != "dev-only-not-for-production"
    assert len(first.secret_key) >= 32


def test_explicit_secret_supports_stable_sessions(monkeypatch, client):
    monkeypatch.setenv("FLASK_SECRET_KEY", "test-only-explicit-high-entropy-secret")
    assert create_app().secret_key == "test-only-explicit-high-entropy-secret"
    assert create_app().secret_key == "test-only-explicit-high-entropy-secret"


def test_empty_environment_secret_does_not_restore_predictable_fallback(monkeypatch, client):
    monkeypatch.setenv("FLASK_SECRET_KEY", "")
    assert create_app().secret_key != "dev-only-not-for-production"
    assert create_app().secret_key != create_app().secret_key


def test_cookie_from_one_default_app_cannot_authorize_another(monkeypatch, client):
    monkeypatch.delenv("FLASK_SECRET_KEY", raising=False)
    first = create_app()
    second = create_app()
    first.config.update(TESTING=True)
    second.config.update(TESTING=True)

    with first.test_client() as original:
        response = original.post(
            "/secure/login",
            data={"username": "alice", "password": "alice-password-1"},
        )
        assert response.status_code == 200
        signed_cookie = original.get_cookie("session")
        assert signed_cookie is not None
        assert original.get("/secure/note/2").status_code == 200

    with second.test_client() as replay:
        replay.set_cookie("session", signed_cookie.value)
        assert replay.get("/secure/note/2").status_code == 401


def test_short_operator_secret_fails_closed_at_startup(monkeypatch, client):
    import pytest

    for weak_secret in (
        "x", "dev-only-not-for-production", " " * 40,
        "x" * 32, "Ab3!" * 8, "12345678" * 4,
    ):
        monkeypatch.setenv("FLASK_SECRET_KEY", weak_secret)
        with pytest.raises(ValueError, match="FLASK_SECRET_KEY"):
            create_app()


def test_minimum_length_operator_secret_is_accepted(monkeypatch, client):
    secret = "aB3!cD4@eF5#gH6$iJ7%kL8^mN9&pQ0*"
    assert len(secret) == 32
    monkeypatch.setenv("FLASK_SECRET_KEY", secret)
    assert create_app().secret_key == secret
