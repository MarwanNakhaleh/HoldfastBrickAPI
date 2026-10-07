"""Shared fixtures (same TestClient dance as tests/test_api.py)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("HOLDFASTBRICK_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("HOLDFASTBRICK_MDNS_ENABLED", "false")
    # Re-import with a clean state dir.
    import importlib

    from holdfastbrick_api import config

    importlib.reload(config)
    from holdfastbrick_api import auth, main

    importlib.reload(auth)
    importlib.reload(main)
    with TestClient(main.app) as test_client:
        yield test_client, auth


@pytest.fixture()
def authed(client):
    """(test_client, auth headers) for a freshly paired token."""
    test_client, auth = client
    code = auth.open_pairing_window()
    resp = test_client.post("/api/v1/pair", json={"code": code, "client_name": "test"})
    assert resp.status_code == 200
    return test_client, {"Authorization": f"Bearer {resp.json()['token']}"}
