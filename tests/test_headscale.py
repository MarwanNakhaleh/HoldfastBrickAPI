"""Headscale household service: CLI wrappers via a fake run(), CA serving,
and the pure parse/extract logic."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from holdfastbrick_api.runner import CommandError, CommandResult
from holdfastbrick_api.services import headscale

FAKE_URL = "https://192.168.1.50"
# Observed verbatim from `headscale preauthkeys create` on v0.29.4.
PREAUTH_KEY = "hskey-auth-WM7OfOMGhxsD-tvwWmVQxrrcPIQru7LD2NdsLJ6NTxmkgPgeTt26FKgdR55ZlOXRQxbzWiBWpdKkF"

USERS_JSON = '[{"id": 7, "name": "family", "created_at": {"seconds": 1690000000}}]'
NO_USERS_JSON = "[]"

NODES_JSON = """\
[
  {"id": 1, "name": "holdfast-brick", "user": {"id": 1, "name": "family"},
   "online": true, "lastSeen": "2026-10-07T12:00:00Z"},
  {"id": 2, "name": "family-ipad", "user": {"id": 1, "name": "family"},
   "online": false, "last_seen": {"seconds": 1791431136, "nanos": 908016793}}
]
"""

NORMALIZED_DEVICES = [
    {
        "id": "1",
        "name": "holdfast-brick",
        "user": "family",
        "online": True,
        "last_seen": "2026-10-07T12:00:00Z",
    },
    {
        "id": "2",
        "name": "family-ipad",
        "user": "family",
        "online": False,
        "last_seen": "2026-10-08T03:45:36+00:00",
    },
]


# --- parse_nodes_json ----------------------------------------------------------


def test_parse_nodes_json_normalizes():
    assert headscale.parse_nodes_json(NODES_JSON) == NORMALIZED_DEVICES


def test_parse_nodes_json_accepts_nodes_wrapped_dict():
    wrapped = '{"nodes": [{"id": 7, "name": "tv", "user": "family", "online": false}]}'
    assert headscale.parse_nodes_json(wrapped) == [
        {"id": "7", "name": "tv", "user": "family", "online": False, "last_seen": ""}
    ]


def test_parse_nodes_json_garbage_is_empty():
    assert headscale.parse_nodes_json("") == []
    assert headscale.parse_nodes_json("not json at all") == []
    assert headscale.parse_nodes_json('{"a": 1}') == []
    assert headscale.parse_nodes_json('{"nodes": "nope"}') == []
    assert headscale.parse_nodes_json("[1, 2]") == []


def test_parse_nodes_json_null_is_empty():
    # Observed v0.29.4: an empty tailnet prints a bare `null`, not `[]`.
    assert headscale.parse_nodes_json("null") == []


# --- family_user_id ------------------------------------------------------------


def test_family_user_id_found():
    assert headscale.family_user_id(USERS_JSON) == 7


def test_family_user_id_absent_or_bad():
    assert headscale.family_user_id(NO_USERS_JSON) is None
    assert headscale.family_user_id("null") is None
    assert headscale.family_user_id("garbage") is None
    assert headscale.family_user_id('[{"id": "x", "name": "family"}]') is None
    assert headscale.family_user_id('[{"id": 3, "name": "someone-else"}]') is None


# --- extract_preauth_key -------------------------------------------------------


def test_extract_preauth_key_bare_line():
    assert headscale.extract_preauth_key(f"{PREAUTH_KEY}\n") == PREAUTH_KEY


def test_extract_preauth_key_after_chatter():
    output = f"user created\nKey: {PREAUTH_KEY}\nexpiration 24h\n"
    assert headscale.extract_preauth_key(output) == PREAUTH_KEY


def test_extract_preauth_key_none_found():
    assert headscale.extract_preauth_key("") == ""
    assert headscale.extract_preauth_key("error: something broke") == ""


# --- count_unused_preauth_keys (enroll cap) --------------------------------------

PARSER_NOW = datetime(2026, 10, 9, 12, 0, 0, tzinfo=timezone.utc)
# Far enough out that these stay unexpired for the whole test-run day.
FUTURE = {"seconds": int(PARSER_NOW.timestamp()) + 30 * 86400}
PAST = {"seconds": int(PARSER_NOW.timestamp()) - 3600}


def _preauth(
    key_id: int,
    *,
    user_id=7,
    used=False,
    expiration=FUTURE,
):
    return {
        "id": key_id,
        "key": "hskey-auth-masked",
        "user": {"id": user_id, "name": "family"},
        "used": used,
        "expiration": expiration,
    }


def test_count_unused_preauth_keys_counts_family_only():
    keys = json.dumps(
        [
            _preauth(1),  # counts
            _preauth(2, used=True),  # used → no
            _preauth(3, expiration=PAST),  # expired → no
            _preauth(4, user_id=9),  # another user → no
            _preauth(5, expiration="2026-10-09T13:00:00Z"),  # ISO string → counts
            _preauth(6, expiration=None),  # unknown expiry counts (safe side)
        ]
    )
    assert headscale.count_unused_preauth_keys(keys, 7, PARSER_NOW) == 3


def test_count_unused_preauth_keys_int_user_shapes():
    keys = json.dumps(
        [
            {"id": 1, "user": 7, "used": False, "expiration": FUTURE},
            {"id": 2, "user": "7", "used": False, "expiration": FUTURE},
        ]
    )
    assert headscale.count_unused_preauth_keys(keys, 7, PARSER_NOW) == 2


def test_count_unused_preauth_keys_tolerates_absence():
    assert headscale.count_unused_preauth_keys("null", 7, PARSER_NOW) == 0
    assert headscale.count_unused_preauth_keys("[]", 7, PARSER_NOW) == 0
    assert headscale.count_unused_preauth_keys("garbage", 7, PARSER_NOW) is None
    assert headscale.count_unused_preauth_keys('{"a": 1}', 7, PARSER_NOW) is None
    # A list whose items aren't key objects reads as "no outstanding keys":
    # the cap is fail-open by design, enrollment must not break over it.
    assert headscale.count_unused_preauth_keys("[1, 2]", 7, PARSER_NOW) == 0


def test_count_unused_preauth_keys_wrapped_dict():
    wrapped = json.dumps({"preAuthKeys": [_preauth(1), _preauth(2, used=True)]})
    assert headscale.count_unused_preauth_keys(wrapped, 7, PARSER_NOW) == 1


# --- fake CLI wiring -----------------------------------------------------------


def _wire_fake_headscale(
    monkeypatch,
    *,
    nodes_json="null",
    key=PREAUTH_KEY,
    users_error="",
    users_lookup=None,
    delete_error="",
    timeout_on_delete=False,
    missing=False,
    preauth_list="null",
    preauth_list_error=False,
):
    calls: list[list[str]] = []
    # Sequence of payloads served by successive `users list -o json` calls;
    # the last one repeats once exhausted.
    lookups = list(users_lookup) if users_lookup is not None else [USERS_JSON]

    async def fake_run(argv, timeout=20.0):
        calls.append(argv)
        if missing:
            raise CommandError(f"binary not installed: {argv[0]}")
        if argv[:2] == ["headscale", "version"]:
            return CommandResult(ok=True, exit_code=0, stdout="1.2.3", stderr="")
        if argv[:3] == ["headscale", "users", "list"]:
            payload = lookups.pop(0) if len(lookups) > 1 else lookups[0]
            return CommandResult(ok=True, exit_code=0, stdout=payload, stderr="")
        if argv[:3] == ["headscale", "users", "create"]:
            if users_error:
                return CommandResult(ok=False, exit_code=1, stdout="", stderr=users_error)
            return CommandResult(ok=True, exit_code=0, stdout="user created", stderr="")
        if argv[:3] == ["headscale", "preauthkeys", "list"]:
            if preauth_list_error:
                raise CommandError("preauthkeys list exploded")
            return CommandResult(ok=True, exit_code=0, stdout=preauth_list, stderr="")
        if argv[:2] == ["headscale", "preauthkeys"]:
            return CommandResult(ok=True, exit_code=0, stdout=f"Key: {key}\n", stderr="")
        if argv[:3] == ["headscale", "nodes", "list"]:
            return CommandResult(ok=True, exit_code=0, stdout=nodes_json, stderr="")
        if argv[:3] == ["headscale", "nodes", "delete"]:
            if timeout_on_delete:
                raise CommandError(f"command timed out after {timeout}s: {' '.join(argv)}")
            if delete_error:
                return CommandResult(ok=False, exit_code=1, stdout="", stderr=delete_error)
            return CommandResult(ok=True, exit_code=0, stdout="node removed", stderr="")
        return CommandResult(ok=True, exit_code=0, stdout="", stderr="")

    async def fake_systemd_status(unit):
        return {"unit": unit, "running": True, "state": "active", "enabled": True}

    monkeypatch.setattr(headscale, "run", fake_run)
    monkeypatch.setattr(headscale, "systemd_status", fake_systemd_status)
    return calls


# --- runner allowlist ----------------------------------------------------------


def test_runner_refuses_disallowed_headscale_subcommand():
    import asyncio

    from holdfastbrick_api import runner

    with pytest.raises(CommandError, match="not allowlisted"):
        asyncio.run(runner.run(["headscale", "serve"]))
    with pytest.raises(CommandError, match="not allowlisted"):
        asyncio.run(runner.run(["headscale"]))


# --- endpoint auth gating ------------------------------------------------------


def test_household_endpoints_require_token(client):
    test_client, _ = client
    assert test_client.get("/api/v1/household/status").status_code == 401
    assert test_client.post(
        "/api/v1/household/enroll", json={"device_name": "iphone"}
    ).status_code == 401
    assert test_client.get("/api/v1/household/devices").status_code == 401
    assert test_client.post("/api/v1/household/devices/1/remove").status_code == 401
    assert test_client.get("/api/v1/household/ca").status_code == 401
    assert test_client.get("/api/v1/household/ca/profile").status_code == 401


# --- /household/status ---------------------------------------------------------


def test_status_reports_devices_when_available(authed, monkeypatch):
    test_client, headers = authed
    monkeypatch.setattr(headscale.settings, "headscale_url", FAKE_URL)
    calls = _wire_fake_headscale(monkeypatch, nodes_json=NODES_JSON)
    resp = test_client.get("/api/v1/household/status", headers=headers)
    assert resp.status_code == 200
    assert resp.json() == {
        "available": True,
        "running": True,
        "url": FAKE_URL,
        "device_count": 2,
        "devices": NORMALIZED_DEVICES,
    }
    assert ["headscale", "nodes", "list", "-o", "json"] in calls


def test_status_headscale_missing_is_200_unavailable(authed, monkeypatch):
    test_client, headers = authed
    calls = _wire_fake_headscale(monkeypatch, missing=True)
    resp = test_client.get("/api/v1/household/status", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["available"] is False
    assert resp.json()["devices"] == []
    assert calls == [["headscale", "version"]]


def test_status_service_not_running_is_unavailable(authed, monkeypatch):
    test_client, headers = authed

    async def stopped_status(unit):
        return {"unit": unit, "running": False, "state": "inactive", "enabled": True}

    calls: list[list[str]] = []

    async def fake_run(argv, timeout=20.0):
        calls.append(argv)
        return CommandResult(ok=True, exit_code=0, stdout="1.2.3", stderr="")

    monkeypatch.setattr(headscale, "run", fake_run)
    monkeypatch.setattr(headscale, "systemd_status", stopped_status)
    resp = test_client.get("/api/v1/household/status", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["available"] is False and body["running"] is False
    # nodes list must not run against a stopped server.
    assert all(argv[1] != "nodes" for argv in calls)


# --- /household/enroll ---------------------------------------------------------


def test_enroll_mints_key_for_existing_family_user(authed, monkeypatch):
    test_client, headers = authed
    monkeypatch.setattr(headscale.settings, "headscale_url", FAKE_URL)
    calls = _wire_fake_headscale(monkeypatch)
    resp = test_client.post(
        "/api/v1/household/enroll", json={"device_name": "iphone"}, headers=headers
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["server_url"] == FAKE_URL
    assert body["auth_key"] == PREAUTH_KEY
    remaining = (
        datetime.fromisoformat(body["expires_at"]) - datetime.now(timezone.utc)
    ).total_seconds()
    assert 86000 < remaining <= 86400
    # The user already exists: a lookup, no create, key minted for the
    # numeric id (`--user` rejects names on v0.29.4).
    assert ["headscale", "users", "list", "-o", "json"] in calls
    assert all(argv[1:3] != ["users", "create"] for argv in calls)
    assert calls[-1] == [
        "headscale",
        "preauthkeys",
        "create",
        "--user",
        "7",
        "--expiration",
        "24h",
    ]


def test_enroll_creates_missing_family_user(authed, monkeypatch):
    test_client, headers = authed
    calls = _wire_fake_headscale(
        monkeypatch, users_lookup=[NO_USERS_JSON, USERS_JSON]
    )
    resp = test_client.post("/api/v1/household/enroll", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["auth_key"] == PREAUTH_KEY
    assert ["headscale", "users", "create", "family"] in calls
    assert calls[-1][4] == "7"


def test_enroll_tolerates_already_exists_race(authed, monkeypatch):
    test_client, headers = authed
    calls = _wire_fake_headscale(
        monkeypatch,
        users_error='Error: user "family" already exists',
        users_lookup=[NO_USERS_JSON, USERS_JSON],
    )
    resp = test_client.post("/api/v1/household/enroll", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["auth_key"] == PREAUTH_KEY


def test_enroll_users_create_failure_is_502(authed, monkeypatch):
    test_client, headers = authed
    calls = _wire_fake_headscale(
        monkeypatch, users_error="database is locked", users_lookup=[NO_USERS_JSON]
    )
    resp = test_client.post("/api/v1/household/enroll", headers=headers)
    assert resp.status_code == 502
    assert "database is locked" in resp.json()["detail"]
    assert all(argv[1] != "preauthkeys" for argv in calls)


def test_enroll_user_still_missing_after_create_is_502(authed, monkeypatch):
    test_client, headers = authed
    calls = _wire_fake_headscale(monkeypatch, users_lookup=[NO_USERS_JSON])
    resp = test_client.post("/api/v1/household/enroll", headers=headers)
    assert resp.status_code == 502
    assert "family user is missing" in resp.json()["detail"]
    assert all(argv[1] != "preauthkeys" for argv in calls)


def test_enroll_503_when_headscale_missing(authed, monkeypatch):
    test_client, headers = authed
    calls = _wire_fake_headscale(monkeypatch, missing=True)
    resp = test_client.post("/api/v1/household/enroll", headers=headers)
    assert resp.status_code == 503
    assert calls == [["headscale", "version"]]


# --- enroll cap on outstanding join keys (M7) -------------------------------------


def test_enroll_429_at_five_outstanding_keys(authed, monkeypatch):
    test_client, headers = authed
    outstanding = json.dumps([_preauth(i) for i in range(1, 6)])
    calls = _wire_fake_headscale(monkeypatch, preauth_list=outstanding)
    resp = test_client.post("/api/v1/household/enroll", headers=headers)
    assert resp.status_code == 429
    detail = resp.json()["detail"]
    assert "5" in detail and "revoke" in detail.lower() and "expir" in detail.lower()
    # The cap must gate the mint: no key was created.
    assert all(argv[1:3] != ["preauthkeys", "create"] for argv in calls)


def test_enroll_allows_four_outstanding_keys(authed, monkeypatch):
    test_client, headers = authed
    outstanding = json.dumps([_preauth(i) for i in range(1, 5)])
    calls = _wire_fake_headscale(monkeypatch, preauth_list=outstanding)
    resp = test_client.post("/api/v1/household/enroll", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["auth_key"] == PREAUTH_KEY
    assert calls[-1] == [
        "headscale",
        "preauthkeys",
        "create",
        "--user",
        "7",
        "--expiration",
        "24h",
    ]


def test_enroll_cap_skipped_when_listing_unparseable(authed, monkeypatch):
    test_client, headers = authed
    calls = _wire_fake_headscale(monkeypatch, preauth_list="not json at all")
    resp = test_client.post("/api/v1/household/enroll", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["auth_key"] == PREAUTH_KEY
    assert calls[-1][1:3] == ["preauthkeys", "create"]


def test_enroll_cap_skipped_when_listing_command_fails(authed, monkeypatch):
    test_client, headers = authed
    calls = _wire_fake_headscale(monkeypatch, preauth_list_error=True)
    resp = test_client.post("/api/v1/household/enroll", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["auth_key"] == PREAUTH_KEY
    assert calls[-1][1:3] == ["preauthkeys", "create"]


# --- /household/devices --------------------------------------------------------


def test_devices_lists_normalized(authed, monkeypatch):
    test_client, headers = authed
    calls = _wire_fake_headscale(monkeypatch, nodes_json=NODES_JSON)
    resp = test_client.get("/api/v1/household/devices", headers=headers)
    assert resp.status_code == 200
    assert resp.json() == {"device_count": 2, "devices": NORMALIZED_DEVICES}
    assert calls == [["headscale", "nodes", "list", "-o", "json"]]


def test_devices_503_when_headscale_missing(authed, monkeypatch):
    test_client, headers = authed
    _wire_fake_headscale(monkeypatch, missing=True)
    resp = test_client.get("/api/v1/household/devices", headers=headers)
    assert resp.status_code == 503


# --- /household/devices/{id}/remove --------------------------------------------


def test_remove_rejects_non_positive_ids(authed, monkeypatch):
    test_client, headers = authed
    calls = _wire_fake_headscale(monkeypatch)
    assert (
        test_client.post("/api/v1/household/devices/abc/remove", headers=headers).status_code
        == 422
    )
    assert (
        test_client.post("/api/v1/household/devices/0/remove", headers=headers).status_code
        == 422
    )
    assert (
        test_client.post("/api/v1/household/devices/-3/remove", headers=headers).status_code
        == 422
    )
    assert calls == []


def test_remove_happy_path_uses_force(authed, monkeypatch):
    test_client, headers = authed
    calls = _wire_fake_headscale(monkeypatch)
    resp = test_client.post("/api/v1/household/devices/5/remove", headers=headers)
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "message": "Device removed from the household network."}
    # --force is load-bearing: without it v0.29.4 prompts y/n, reads EOF,
    # prints "Node not deleted", and exits 0 — a silent no-op.
    assert calls == [
        ["headscale", "nodes", "delete", "--identifier", "5", "--force"]
    ]


def test_remove_confirmation_prompt_is_409(authed, monkeypatch):
    test_client, headers = authed
    _wire_fake_headscale(monkeypatch, delete_error="Remove this node? [y/N]: ")
    resp = test_client.post("/api/v1/household/devices/5/remove", headers=headers)
    assert resp.status_code == 409
    assert "on the brick" in resp.json()["detail"]


def test_remove_timeout_points_at_device_cli(authed, monkeypatch):
    test_client, headers = authed
    _wire_fake_headscale(monkeypatch, timeout_on_delete=True)
    resp = test_client.post("/api/v1/household/devices/5/remove", headers=headers)
    assert resp.status_code == 409
    assert "nodes delete --identifier" in resp.json()["detail"]


def test_remove_other_failure_is_502(authed, monkeypatch):
    test_client, headers = authed
    _wire_fake_headscale(monkeypatch, delete_error="node not found")
    resp = test_client.post("/api/v1/household/devices/99/remove", headers=headers)
    assert resp.status_code == 502
    assert "node not found" in resp.json()["detail"]


# --- /household/ca and /ca/profile ---------------------------------------------


def test_ca_serves_pem(authed, monkeypatch, tmp_path):
    test_client, headers = authed
    ca = tmp_path / "ca.crt"
    ca.write_bytes(b"-----BEGIN CERTIFICATE-----\nabc==\n-----END CERTIFICATE-----\n")
    monkeypatch.setattr(headscale.settings, "headscale_ca_cert", ca)
    resp = test_client.get("/api/v1/household/ca", headers=headers)
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/x-x509-ca-cert"
    assert resp.content == ca.read_bytes()


def test_ca_404_when_provisioning_hasnt_run(authed, monkeypatch, tmp_path):
    test_client, headers = authed
    monkeypatch.setattr(headscale.settings, "headscale_ca_cert", tmp_path / "missing.crt")
    resp = test_client.get("/api/v1/household/ca", headers=headers)
    assert resp.status_code == 404
    assert "provisioning" in resp.json()["detail"]


def test_ca_profile_served_from_same_dir(authed, monkeypatch, tmp_path):
    test_client, headers = authed
    ca = tmp_path / "ca.crt"
    ca.write_bytes(b"-----BEGIN CERTIFICATE-----\nabc==\n")
    profile = tmp_path / headscale.MOBILECONFIG_NAME
    profile.write_bytes(b"<plist version=\"1.0\"></plist>")
    monkeypatch.setattr(headscale.settings, "headscale_ca_cert", ca)
    resp = test_client.get("/api/v1/household/ca/profile", headers=headers)
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/x-apple-aspen-config"
    assert resp.content == profile.read_bytes()


def test_ca_profile_404_when_absent_even_with_ca(authed, monkeypatch, tmp_path):
    test_client, headers = authed
    ca = tmp_path / "ca.crt"
    ca.write_bytes(b"-----BEGIN CERTIFICATE-----\nabc==\n")
    monkeypatch.setattr(headscale.settings, "headscale_ca_cert", ca)
    resp = test_client.get("/api/v1/household/ca/profile", headers=headers)
    assert resp.status_code == 404
