import pytest

import app as app_module


@pytest.fixture()
def client(tmp_path, monkeypatch):
    # Isolate each test database and restore DB_PATH after the test.
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(app_module, "DB_PATH", db_path)
    app_module.init_db(db_path)
    flask_app = app_module.create_app()
    flask_app.config.update(TESTING=True)
    with flask_app.test_client() as c:
        yield c
