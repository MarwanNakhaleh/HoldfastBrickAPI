"""Smoke tests that run anywhere (no Pi services required)."""

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
    from holdfastbrick_api.services import system

    importlib.reload(system)
    importlib.reload(main)
    # Host "localhost" passes the DNS-rebinding guard (see conftest.py).
    with TestClient(main.app, base_url="http://localhost") as test_client:
        yield test_client, auth


def _pair(test_client, auth) -> dict:
    """Pair and return auth headers for a fresh token."""
    code = auth.open_pairing_window()
    resp = test_client.post("/api/v1/pair", json={"code": code, "client_name": "test"})
    assert resp.status_code == 200
    return {"Authorization": f"Bearer {resp.json()['token']}"}


def test_ping_is_unauthenticated(client):
    test_client, _ = client
    resp = test_client.get("/api/v1/ping")
    assert resp.status_code == 200
    assert resp.json()["app"] == "holdfastbrick"


def test_overview_requires_token(client):
    test_client, _ = client
    assert test_client.get("/api/v1/overview").status_code == 401


def test_pairing_flow(client):
    test_client, auth = client
    code = auth.open_pairing_window()

    wrong = test_client.post("/api/v1/pair", json={"code": "000000", "client_name": "t"})
    # A wrong guess must not consume the window unless it matched.
    if code != "000000":
        assert wrong.status_code == 403

    resp = test_client.post("/api/v1/pair", json={"code": code, "client_name": "test"})
    assert resp.status_code == 200
    token = resp.json()["token"]

    # Token unlocks authenticated endpoints (overview may 200 even when the
    # underlying services are absent — health() degrades gracefully).
    resp = test_client.get(
        "/api/v1/overview", headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "services" in body and isinstance(body["services"], list)

    # Codes are single-use.
    resp = test_client.post("/api/v1/pair", json={"code": code, "client_name": "again"})
    assert resp.status_code == 403


def test_identity_requires_token(client):
    test_client, _ = client
    assert test_client.get("/api/v1/identity").status_code == 401


def test_identity_shape(client):
    test_client, auth = client
    resp = test_client.get("/api/v1/identity", headers=_pair(test_client, auth))
    assert resp.status_code == 200
    body = resp.json()
    assert set(body) == {
        "device_name", "version", "port", "lan_ip", "tailscale_ips", "magicdns_name"
    }
    assert isinstance(body["port"], int)
    # No tailscale CLI in the test environment → graceful empty values.
    assert body["tailscale_ips"] == []
    assert body["magicdns_name"] == ""


def test_adguard_endpoints_require_token(client):
    test_client, _ = client
    assert test_client.get("/api/v1/adguard/querylog").status_code == 401
    assert test_client.get("/api/v1/adguard/blocklists").status_code == 401
    assert test_client.post("/api/v1/adguard/blocklists", json={"url": "u", "name": "n"}).status_code == 401
    assert test_client.post("/api/v1/adguard/blocklists/remove", json={"url": "u"}).status_code == 401
    assert test_client.post(
        "/api/v1/adguard/rules", json={"domain": "ads.example.com", "action": "deny"}
    ).status_code == 401


def test_adguard_unreachable_degrades_to_503(client):
    test_client, auth = client
    headers = _pair(test_client, auth)
    assert test_client.get("/api/v1/adguard/querylog", headers=headers).status_code == 503
    assert test_client.get("/api/v1/adguard/blocklists", headers=headers).status_code == 503
    assert test_client.post(
        "/api/v1/adguard/blocklists",
        json={"url": "https://example.com/list.txt", "name": "Example"},
        headers=headers,
    ).status_code == 503
    assert test_client.post(
        "/api/v1/adguard/blocklists/remove",
        json={"url": "https://example.com/list.txt"},
        headers=headers,
    ).status_code == 503
    assert test_client.post(
        "/api/v1/adguard/rules",
        json={"domain": "ads.example.com", "action": "deny"},
        headers=headers,
    ).status_code == 503


def test_adguard_rules_validates_domain(client):
    test_client, auth = client
    headers = _pair(test_client, auth)
    for bad in ("http://evil.com", "evil.com/path", "-bad-.com", "no dots"):
        resp = test_client.post(
            "/api/v1/adguard/rules", json={"domain": bad, "action": "deny"}, headers=headers
        )
        assert resp.status_code == 422, bad
    resp = test_client.post(
        "/api/v1/adguard/rules", json={"domain": "ok.example.com", "action": "maybe"}, headers=headers
    )
    assert resp.status_code == 422


def test_adguard_auth_failure_maps_to_actionable_502():
    """A 401/403 from AdGuard is a credentials problem, not 'unreachable'."""
    import httpx

    from holdfastbrick_api.services import adguard

    request = httpx.Request("GET", "http://127.0.0.1:3000/control/stats")
    auth_exc = httpx.HTTPStatusError(
        "unauthorized", request=request, response=httpx.Response(401, request=request)
    )
    err = adguard._proxy_error(auth_exc)
    assert err.status_code == 502
    assert "/etc/holdfastbrick/.env" in err.detail
    assert "unreachable" not in err.detail.lower()

    transport_exc = httpx.ConnectError("connection refused", request=request)
    assert adguard._proxy_error(transport_exc).status_code == 503
