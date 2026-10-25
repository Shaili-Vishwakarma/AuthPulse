"""Conftest for AuthPulse tests."""
import os
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def app(tmp_path):
    """Flask app with an isolated temporary database."""
    os.environ["AUTHPULSE_SECRET"] = "test-secret"
    # Set DB path via env var so init_db() (runs at import time) uses temp dir
    db_path = str(tmp_path / "test.db")
    os.environ["AUTHPULSE_DB_PATH"] = db_path

    import importlib
    import app as app_module
    importlib.reload(app_module)

    # Verify the env var was picked up
    assert str(app_module.DB_PATH) == db_path, f"DB_PATH mismatch: {app_module.DB_PATH} != {db_path}"
    app_module.init_db()

    app_module.app.config["TESTING"] = True
    return app_module


@pytest.fixture
def client(app):
    return app.app.test_client()


@pytest.fixture
def secret(app):
    return app.HMAC_SECRET
