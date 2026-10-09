"""Security-hardening behavior from the 2026-10-09 audit: pairing lockout
and rate limit (H1), token revocation (H2), the DNS-rebinding host guard
(M4), disabled docs (M3), and TLS identity plumbing (S1's API half)."""

from __future__ import annotations

import base64
import hashlib
import json

import pytest
import uvicorn

from holdfastbrick_api import auth, config, main


def _wrong_code_for(code: str, n: int) -> str:
    """A 6-digit code that is definitely not ``code``."""
    candidate = f"{n:06d}"
    return "999999" if candidate == code else candidate


# --- pairing lockout (H1) ------------------------------------------------------


def test_five_wrong_codes_clear_the_window(client):
    test_client, auth_module = client
    code = auth_module.open_pairing_window()
    for n in range(1, 6):
        resp = test_client.post(
            "/api/v1/pair", json={"code": _wrong_code_for(code, n), "client_name": "t"}
        )
        assert resp.status_code == 403
    # The window is gone entirely: even the correct code is refused, and a
    # new one requires running holdfastbrick-pair on the brick again.
    resp = test_client.post("/api/v1/pair", json={"code": code, "client_name": "t"})
    assert resp.status_code == 403
    assert "holdfastbrick-pair" in resp.json()["detail"]
    assert auth_module.state.get_pairing() is None


def test_four_wrong_codes_leave_the_window_open(client):
    test_client, auth_module = client
    code = auth_module.open_pairing_window()
    for n in range(1, 5):
        resp = test_client.post(
            "/api/v1/pair", json={"code": _wrong_code_for(code, n), "client_name": "t"}
        )
        assert resp.status_code == 403
    resp = test_client.post("/api/v1/pair", json={"code": code, "client_name": "t"})
    assert resp.status_code == 200


def test_successful_pair_resets_the_failure_counter(client):
    test_client, auth_module = client
    code = auth_module.open_pairing_window()
    for n in range(1, 5):
        test_client.post(
            "/api/v1/pair", json={"code": _wrong_code_for(code, n), "client_name": "t"}
        )
    assert (
        test_client.post("/api/v1/pair", json={"code": code, "client_name": "t"}).status_code
        == 200
    )
    # A second window survives another four wrong codes: the slate was wiped.
    code = auth_module.open_pairing_window()
    for n in range(1, 5):
        resp = test_client.post(
            "/api/v1/pair", json={"code": _wrong_code_for(code, n), "client_name": "t"}
        )
        assert resp.status_code == 403
    assert (
        test_client.post("/api/v1/pair", json={"code": code, "client_name": "t"}).status_code
        == 200
    )


def test_pairing_failure_counter_is_persisted(tmp_path):
    api = config.StateStore(tmp_path)
    api.record_pairing_failure()
    api.record_pairing_failure()
    fresh = config.StateStore(tmp_path)
    assert fresh.record_pairing_failure() == 3
    fresh.clear_pairing_failures()
    assert config.StateStore(tmp_path).record_pairing_failure() == 1


# --- per-address pairing rate limit (H1) ----------------------------------------


def test_pair_limiter_trips_429(client):
    test_client, auth_module = client
    code = auth_module.open_pairing_window()
    wrong = _wrong_code_for(code, 1)
    for _ in range(auth.CODED_GATE_LIMIT):
        assert (
            test_client.post("/api/v1/pair", json={"code": wrong, "client_name": "t"}).status_code
            == 403
        )
    resp = test_client.post("/api/v1/pair", json={"code": wrong, "client_name": "t"})
    assert resp.status_code == 429
    assert "wait" in resp.json()["detail"].lower()


def test_pair_attempt_allowed_is_a_sliding_window():
    auth._gate_attempts.clear()
    for t in range(auth.CODED_GATE_LIMIT):
        assert auth.pair_attempt_allowed("1.2.3.4", now=t)
    assert not auth.pair_attempt_allowed("1.2.3.4", now=auth.CODED_GATE_LIMIT)
    # The oldest attempts slide out of the window and the address frees up.
    assert auth.pair_attempt_allowed(
        "1.2.3.4", now=auth.CODED_GATE_LIMIT + auth.CODED_GATE_WINDOW_SECONDS
    )


def test_pair_limiter_is_per_source_address():
    auth._gate_attempts.clear()
    for t in range(auth.CODED_GATE_LIMIT):
        auth.pair_attempt_allowed("1.1.1.1", now=t)
    assert not auth.pair_attempt_allowed("1.1.1.1", now=auth.CODED_GATE_LIMIT)
    assert auth.pair_attempt_allowed("2.2.2.2", now=auth.CODED_GATE_LIMIT)


# --- token list + revocation (H2) ------------------------------------------------


def test_auth_tokens_require_token(client):
    test_client, _ = client
    assert test_client.get("/api/v1/auth/tokens").status_code == 401
    assert test_client.delete("/api/v1/auth/tokens/self").status_code == 401
    assert test_client.delete("/api/v1/auth/tokens/abc123").status_code == 401


def test_tokens_list_masks_token_values(authed):
    test_client, headers = authed
    resp = test_client.get("/api/v1/auth/tokens", headers=headers)
    assert resp.status_code == 200
    listing = resp.json()
    assert len(listing) == 1
    raw = headers["Authorization"].removeprefix("Bearer ")
    assert listing[0]["id"] == hashlib.sha256(raw.encode()).hexdigest()[:12]
    assert raw not in json.dumps(listing)
    assert listing[0]["client_name"] == "test"
    assert isinstance(listing[0]["created_at"], float)


def test_legacy_token_without_created_at_is_listed_and_revocable(client):
    test_client, auth_module = client
    # Simulate a token minted by an older version: no created_at on disk.
    state_path = auth_module.state._path
    data = json.loads(state_path.read_text()) if state_path.exists() else {}
    data.setdefault("tokens", {})["legacy-raw-token"] = {"client": "old-phone"}
    state_path.write_text(json.dumps(data))

    code = auth_module.open_pairing_window()
    resp = test_client.post("/api/v1/pair", json={"code": code, "client_name": "new"})
    assert resp.status_code == 200
    headers = {"Authorization": f"Bearer {resp.json()['token']}"}

    listing = test_client.get("/api/v1/auth/tokens", headers=headers).json()
    legacy = next(entry for entry in listing if entry["client_name"] == "old-phone")
    assert legacy["created_at"] is None
    # The old token keeps working (tolerant read) and can still be revoked.
    assert test_client.get(
        "/api/v1/overview", headers={"Authorization": "Bearer legacy-raw-token"}
    ).status_code == 200
    assert (
        test_client.delete(f"/api/v1/auth/tokens/{legacy['id']}", headers=headers).status_code
        == 200
    )
    assert test_client.get(
        "/api/v1/overview", headers={"Authorization": "Bearer legacy-raw-token"}
    ).status_code == 401


def test_revoke_by_id_cuts_off_that_device_only(authed):
    test_client, headers = authed
    code = auth.open_pairing_window()
    second = test_client.post(
        "/api/v1/pair", json={"code": code, "client_name": "second"}
    ).json()["token"]
    listing = test_client.get("/api/v1/auth/tokens", headers=headers).json()
    second_id = next(entry["id"] for entry in listing if entry["client_name"] == "second")

    resp = test_client.delete(f"/api/v1/auth/tokens/{second_id}", headers=headers)
    assert resp.status_code == 200
    assert test_client.get(
        "/api/v1/overview", headers={"Authorization": f"Bearer {second}"}
    ).status_code == 401
    # The revoking device is untouched.
    assert test_client.get("/api/v1/overview", headers=headers).status_code == 200
    assert (
        test_client.delete("/api/v1/auth/tokens/deadbeefcafe", headers=headers).status_code
        == 404
    )


def test_revoke_self_then_401(authed):
    test_client, headers = authed
    assert test_client.delete("/api/v1/auth/tokens/self", headers=headers).status_code == 200
    assert test_client.get("/api/v1/overview", headers=headers).status_code == 401


# --- DNS-rebinding host guard (M4) ------------------------------------------------


@pytest.mark.parametrize(
    "host,expected",
    [
        ("", True),  # HTTP/1.0 clients send no Host at all
        ("localhost", True),
        ("localhost:8787", True),
        ("LOCALHOST", True),
        ("localhost.", True),
        ("127.0.0.1", True),
        ("127.0.0.1:8787", True),
        ("::1", True),
        ("[::1]:8787", True),
        ("192.168.1.50", True),
        ("192.168.1.50:8787", True),
        ("100.101.102.103", True),  # tailnet IPv4 literal
        ("fd7a:115c:a1e0::1", True),  # tailnet IPv6 literal
        ("brick.local", True),
        ("Holdfast-Brick.local.", True),
        ("brick.ts.net", True),
        ("evil.com", False),
        ("evil.com:8443", False),
        ("example.com", False),
        ("notlocal", False),
        ("local.evil.com", False),
        ("ts.net.evil.com", False),
        ("testclient", False),  # TestClient's default host
    ],
)
def test_classify_host_table(host, expected):
    assert main.classify_host(host, []) is expected


def test_classify_host_honors_settings_extras():
    assert main.classify_host("brick.example.com", ["brick.example.com"])
    assert main.classify_host("Brick.Example.com.", ["brick.example.com"])
    assert main.classify_host("brick.example.com:8787", ["brick.example.com"])
    assert not main.classify_host("other.example.com", ["brick.example.com"])


def test_dns_rebinding_host_header_is_rejected(client):
    test_client, _ = client
    resp = test_client.get("/api/v1/ping", headers={"Host": "evil.com"})
    assert resp.status_code == 400
    assert "brick" in resp.json()["detail"].lower()
    # The normal local host is untouched.
    assert test_client.get("/api/v1/ping").status_code == 200


# --- interactive docs are gone (M3) ------------------------------------------------


def test_docs_endpoints_disabled(client):
    test_client, _ = client
    assert test_client.get("/docs").status_code == 404
    assert test_client.get("/redoc").status_code == 404
    assert test_client.get("/openapi.json").status_code == 404


# --- TLS identity plumbing (S1 API half) --------------------------------------------


def _write_pem(path, der: bytes):
    b64 = base64.b64encode(der).decode()
    lines = "\n".join(b64[i : i + 64] for i in range(0, len(b64), 64))
    path.write_text(
        f"-----BEGIN CERTIFICATE-----\n{lines}\n-----END CERTIFICATE-----\n"
    )


def test_ping_fingerprint_null_when_tls_disabled(client, monkeypatch):
    test_client, _ = client
    monkeypatch.setattr(main.settings, "tls_cert", "")
    monkeypatch.setattr(main.settings, "tls_key", "")
    assert test_client.get("/api/v1/ping").json()["cert_fingerprint"] is None


def test_ping_fingerprint_null_when_cert_files_missing(client, monkeypatch, tmp_path):
    test_client, _ = client
    monkeypatch.setattr(main.settings, "tls_cert", str(tmp_path / "missing.crt"))
    monkeypatch.setattr(main.settings, "tls_key", str(tmp_path / "missing.key"))
    assert test_client.get("/api/v1/ping").json()["cert_fingerprint"] is None


def test_ping_and_pair_carry_cert_fingerprint(client, monkeypatch, tmp_path):
    test_client, auth_module = client
    der = bytes(range(64))
    _write_pem(tmp_path / "server.crt", der)
    (tmp_path / "server.key").write_text("key material")
    monkeypatch.setattr(main.settings, "tls_cert", str(tmp_path / "server.crt"))
    monkeypatch.setattr(main.settings, "tls_key", str(tmp_path / "server.key"))
    expected = hashlib.sha256(der).hexdigest()

    assert test_client.get("/api/v1/ping").json()["cert_fingerprint"] == expected
    code = auth_module.open_pairing_window()
    body = test_client.post("/api/v1/pair", json={"code": code, "client_name": "t"}).json()
    assert body["cert_fingerprint"] == expected


def test_cert_fingerprint_pure_function(tmp_path, monkeypatch):
    cert = tmp_path / "server.crt"
    _write_pem(cert, b"\x30\x82\x01\x02")
    monkeypatch.setattr(config.settings, "tls_cert", str(cert))
    assert config.cert_fingerprint() == hashlib.sha256(b"\x30\x82\x01\x02").hexdigest()

    cert.write_text("not a pem")
    assert config.cert_fingerprint() is None
    monkeypatch.setattr(config.settings, "tls_cert", "")
    assert config.cert_fingerprint() is None


def test_main_enables_tls_when_material_exists(monkeypatch, tmp_path):
    cert = tmp_path / "server.crt"
    key = tmp_path / "server.key"
    _write_pem(cert, b"\x01")
    key.write_text("key material")
    monkeypatch.setattr(main.settings, "tls_cert", str(cert))
    monkeypatch.setattr(main.settings, "tls_key", str(key))

    captured = {}

    def fake_run(app, host=None, port=None, **kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(uvicorn, "run", fake_run)
    main.main()
    assert captured["ssl_certfile"] == str(cert)
    assert captured["ssl_keyfile"] == str(key)


def test_main_stays_http_when_tls_disabled(monkeypatch, tmp_path):
    monkeypatch.setattr(main.settings, "tls_cert", "")
    monkeypatch.setattr(main.settings, "tls_key", "")
    captured = {}

    def fake_run(app, host=None, port=None, **kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(uvicorn, "run", fake_run)
    main.main()
    assert "ssl_certfile" not in captured
    assert "ssl_keyfile" not in captured


def test_main_stays_http_when_cert_files_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(main.settings, "tls_cert", str(tmp_path / "no.crt"))
    monkeypatch.setattr(main.settings, "tls_key", str(tmp_path / "no.key"))
    captured = {}

    def fake_run(app, host=None, port=None, **kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(uvicorn, "run", fake_run)
    main.main()
    assert "ssl_certfile" not in captured


def test_mdns_txt_advertises_tls_only_when_enabled(monkeypatch, tmp_path):
    monkeypatch.setattr(main.settings, "tls_cert", "")
    monkeypatch.setattr(main.settings, "tls_key", "")
    assert "tls" not in main._mdns_properties()

    cert = tmp_path / "server.crt"
    key = tmp_path / "server.key"
    _write_pem(cert, b"\x01")
    key.write_text("k")
    monkeypatch.setattr(main.settings, "tls_cert", str(cert))
    monkeypatch.setattr(main.settings, "tls_key", str(key))
    assert main._mdns_properties()["tls"] == "1"


def test_tls_enabled_requires_both_files(monkeypatch, tmp_path):
    cert = tmp_path / "server.crt"
    key = tmp_path / "server.key"
    monkeypatch.setattr(config.settings, "tls_cert", str(cert))
    monkeypatch.setattr(config.settings, "tls_key", str(key))
    assert config.settings.tls_enabled() is False
    _write_pem(cert, b"\x01")
    assert config.settings.tls_enabled() is False
    key.write_text("k")
    assert config.settings.tls_enabled() is True
    monkeypatch.setattr(config.settings, "tls_cert", "")
    assert config.settings.tls_enabled() is False
