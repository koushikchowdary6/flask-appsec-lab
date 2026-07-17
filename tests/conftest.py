import tempfile
from pathlib import Path

import pytest

import app as app_module


@pytest.fixture()
def client():
    # Point the app at a throwaway database so tests never touch lab.db.
    tmp = Path(tempfile.mkdtemp()) / "test.db"
    app_module.DB_PATH = tmp
    app_module.init_db(tmp)
    flask_app = app_module.create_app()
    flask_app.config.update(TESTING=True)
    with flask_app.test_client() as c:
        yield c
