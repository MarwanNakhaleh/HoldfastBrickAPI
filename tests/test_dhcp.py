"""DHCP takeover: pure-logic unit tests + endpoint tests with a fake AdGuard."""

from __future__ import annotations

import pytest

from holdfastbrick_api.services import dhcp, system

# --- pick_dhcp_range ----------------------------------------------------------


def test_pick_range_first_candidate_when_free():
    assert dhcp.pick_dhcp_range("192.168.1.230", "192.168.1.1") == (
        "192.168.1.100",
        "192.168.1.199",
    )


def test_pick_range_skips_candidate_containing_pi():
    assert dhcp.pick_dhcp_range("192.168.1.150", "192.168.1.1") == (
        "192.168.1.200",
        "192.168.1.249",
    )


def test_pick_range_skips_candidates_containing_gateway():
    # Gateway occupies the first candidate, the Pi the second → third wins.
    assert dhcp.pick_dhcp_range("10.0.0.220", "10.0.0.100") == ("10.0.0.10", "10.0.0.99")


def test_pick_range_ignores_gateway_outside_subnet():
    assert dhcp.pick_dhcp_range("192.168.1.50", "10.0.0.1") == (
        "192.168.1.100",
        "192.168.1.199",
    )


# --- rewrite_interfaces_static ------------------------------------------------

SAMPLE_INTERFACES = """\
# interfaces(5) file used by ifup(8) and ifdown(8)
auto lo
iface lo inet loopback

allow-hotplug eth0
iface eth0 inet dhcp
"""


def test_rewrite_dhcp_to_static_preserves_other_stanzas():
    out = dhcp.rewrite_interfaces_static(
        SAMPLE_INTERFACES, "eth0", "192.168.1.230", "255.255.255.0", "192.168.1.1"
    )
    assert "iface eth0 inet static" in out
    assert "address 192.168.1.230" in out
    assert "netmask 255.255.255.0" in out
    assert "gateway 192.168.1.1" in out
    assert "dns-nameservers 127.0.0.1" in out
    # Everything else untouched.
    assert "iface lo inet loopback" in out
    assert "allow-hotplug eth0" in out
    assert "# interfaces(5) file used by ifup(8) and ifdown(8)" in out
    assert "inet dhcp" not in out


def test_rewrite_unrecognized_file_raises():
    already_static = "iface eth0 inet static\n    address 1.2.3.4\n"
    with pytest.raises(ValueError):
        dhcp.rewrite_interfaces_static(
            already_static, "eth0", "192.168.1.230", "255.255.255.0", "192.168.1.1"
        )


def test_rewrite_wrong_interface_raises():
    with pytest.raises(ValueError):
        dhcp.rewrite_interfaces_static(
            SAMPLE_INTERFACES, "wlan0", "192.168.1.230", "255.255.255.0", "192.168.1.1"
        )


# --- pick_lan_interface -------------------------------------------------------

ADGUARD_INTERFACES = {
    "lo": {"name": "lo", "gateway_ip": "", "ipv4_addresses": ["127.0.0.1"]},
    "wlan0": {"name": "wlan0", "gateway_ip": "192.168.1.1", "ipv4_addresses": ["192.168.1.77"]},
    "eth0": {"name": "eth0", "gateway_ip": "192.168.1.1", "ipv4_addresses": ["192.168.1.230"]},
}


def test_pick_lan_interface_prefers_default_route():
    picked = dhcp.pick_lan_interface(ADGUARD_INTERFACES, "eth0")
    assert picked is not None and picked["name"] == "eth0"


def test_pick_lan_interface_falls_back_to_any_with_gateway():
    picked = dhcp.pick_lan_interface(ADGUARD_INTERFACES, None)
    assert picked is not None and picked["gateway_ip"] == "192.168.1.1"


def test_pick_lan_interface_none_when_no_gateway():
    assert dhcp.pick_lan_interface({"lo": {"name": "lo", "gateway_ip": ""}}, None) is None


# --- fake AdGuard client ------------------------------------------------------


class FakeResponse:
    def __init__(self, data, status_code=200):
        self._data = data
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            import httpx

            request = httpx.Request("GET", "http://127.0.0.1:3000/")
            raise httpx.HTTPStatusError(
                "error", request=request, response=httpx.Response(self.status_code, request=request)
            )

    def json(self):
        return self._data


class FakeAdGuard:
    """Stands in for the httpx.AsyncClient returned by adguard._client()."""

    def __init__(self, get_routes=None, post_routes=None):
        self.get_routes = get_routes or {}
        self.post_routes = post_routes or {}
        self.posts: list[tuple[str, dict | None]] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, path, **kwargs):
        return FakeResponse(self.get_routes[path])

    async def post(self, path, json=None, **kwargs):
        self.posts.append((path, json))
        return FakeResponse(self.post_routes.get(path, {}))


def _wire_fake(monkeypatch, fake):
    monkeypatch.setattr(dhcp, "_client", lambda: fake)


def _wire_route_file(monkeypatch, tmp_path, iface="eth0", gateway_hex="0101A8C0"):
    route = tmp_path / "route"
    route.write_text(
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
        f"{iface}\t00000000\t{gateway_hex}\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
        f"{iface}\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"
    )
    monkeypatch.setattr(system, "ROUTE_FILE", route)


FIND_ACTIVE_CLEAN = {
    "v4": {"other_server": {"found": "no"}, "static_ip": {"static": "yes"}}
}


# --- endpoint auth gating -----------------------------------------------------


def test_dhcp_endpoints_require_token(client):
    test_client, _ = client
    assert test_client.get("/api/v1/dhcp/status").status_code == 401
    assert test_client.post("/api/v1/dhcp/check").status_code == 401
    assert test_client.post("/api/v1/dhcp/enable", json={"force": False}).status_code == 401
    assert test_client.post("/api/v1/dhcp/disable").status_code == 401


# --- /dhcp/status -------------------------------------------------------------


def test_status_normalizes_adguard_shape(authed, monkeypatch):
    test_client, headers = authed
    fake = FakeAdGuard(
        get_routes={
            "/control/dhcp/status": {
                "enabled": True,
                "interface_name": "eth0",
                "v4": {
                    "gateway_ip": "192.168.1.1",
                    "subnet_mask": "255.255.255.0",
                    "range_start": "192.168.1.100",
                    "range_end": "192.168.1.199",
                    "lease_duration": 86400,
                },
                "leases": [{"ip": "192.168.1.101"}, {"ip": "192.168.1.102"}],
            }
        }
    )
    _wire_fake(monkeypatch, fake)
    resp = test_client.get("/api/v1/dhcp/status", headers=headers)
    assert resp.status_code == 200
    assert resp.json() == {
        "enabled": True,
        "interface": "eth0",
        "gateway": "192.168.1.1",
        "range_start": "192.168.1.100",
        "range_end": "192.168.1.199",
        "lease_count": 2,
    }


def test_status_disabled_gives_empty_values(authed, monkeypatch):
    test_client, headers = authed
    _wire_fake(monkeypatch, FakeAdGuard(get_routes={"/control/dhcp/status": {"enabled": False}}))
    resp = test_client.get("/api/v1/dhcp/status", headers=headers)
    assert resp.status_code == 200
    assert resp.json() == {
        "enabled": False,
        "interface": "",
        "gateway": "",
        "range_start": "",
        "range_end": "",
        "lease_count": 0,
    }


def test_status_adguard_down_is_503(authed):
    test_client, headers = authed
    # No AdGuard in the test environment → transport error → 503.
    assert test_client.get("/api/v1/dhcp/status", headers=headers).status_code == 503


# --- /dhcp/check --------------------------------------------------------------


def test_check_reports_interface_and_findings(authed, monkeypatch, tmp_path):
    test_client, headers = authed
    _wire_route_file(monkeypatch, tmp_path)
    fake = FakeAdGuard(
        get_routes={"/control/dhcp/interfaces": ADGUARD_INTERFACES},
        post_routes={
            "/control/dhcp/find_active_dhcp": {
                "v4": {
                    "other_server": {"found": "yes", "error": ""},
                    "static_ip": {"static": "no"},
                }
            }
        },
    )
    _wire_fake(monkeypatch, fake)
    resp = test_client.post("/api/v1/dhcp/check", headers=headers)
    assert resp.status_code == 200
    assert resp.json() == {
        "interface": "eth0",
        "pi_ip": "192.168.1.230",
        "gateway_ip": "192.168.1.1",
        "other_dhcp": "yes",
        "other_dhcp_error": "",
        "static_ip": "no",
    }
    assert fake.posts[0] == ("/control/dhcp/find_active_dhcp", {"interface": "eth0"})


# --- /dhcp/enable -------------------------------------------------------------


def test_enable_blocked_while_router_dhcp_on(authed, monkeypatch, tmp_path):
    test_client, headers = authed
    _wire_route_file(monkeypatch, tmp_path)
    fake = FakeAdGuard(
        get_routes={"/control/dhcp/interfaces": ADGUARD_INTERFACES},
        post_routes={
            "/control/dhcp/find_active_dhcp": {
                "v4": {"other_server": {"found": "yes"}, "static_ip": {"static": "yes"}}
            }
        },
    )
    _wire_fake(monkeypatch, fake)
    resp = test_client.post("/api/v1/dhcp/enable", json={"force": False}, headers=headers)
    assert resp.status_code == 409
    assert "turn it off first" in resp.json()["detail"]
    # set_config must never have been called.
    assert all(path != "/control/dhcp/set_config" for path, _ in fake.posts)


def test_enable_force_overrides_other_dhcp_guard(authed, monkeypatch, tmp_path):
    test_client, headers = authed
    _wire_route_file(monkeypatch, tmp_path)
    fake = FakeAdGuard(
        get_routes={"/control/dhcp/interfaces": ADGUARD_INTERFACES},
        post_routes={
            "/control/dhcp/find_active_dhcp": {
                "v4": {"other_server": {"found": "yes"}, "static_ip": {"static": "yes"}}
            },
            "/control/dhcp/set_config": {},
        },
    )
    _wire_fake(monkeypatch, fake)
    resp = test_client.post("/api/v1/dhcp/enable", json={"force": True}, headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True and body["needs_reboot"] is False


def test_enable_pins_static_ip_and_sets_config(authed, monkeypatch, tmp_path):
    test_client, headers = authed
    _wire_route_file(monkeypatch, tmp_path)
    interfaces_file = tmp_path / "interfaces"
    interfaces_file.write_text(SAMPLE_INTERFACES)
    backup_file = tmp_path / "interfaces.holdfastbrick-bak"
    monkeypatch.setattr(dhcp, "INTERFACES_FILE", interfaces_file)
    monkeypatch.setattr(dhcp, "INTERFACES_BACKUP", backup_file)
    monkeypatch.setattr(dhcp, "_interface_netmask", lambda iface: "255.255.255.0")
    fake = FakeAdGuard(
        get_routes={"/control/dhcp/interfaces": ADGUARD_INTERFACES},
        post_routes={
            "/control/dhcp/find_active_dhcp": {
                "v4": {"other_server": {"found": "no"}, "static_ip": {"static": "no"}}
            },
            "/control/dhcp/set_config": {},
        },
    )
    _wire_fake(monkeypatch, fake)

    resp = test_client.post("/api/v1/dhcp/enable", json={"force": False}, headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["needs_reboot"] is True

    # The interfaces file was backed up and rewritten to a static stanza.
    assert backup_file.read_text() == SAMPLE_INTERFACES
    rewritten = interfaces_file.read_text()
    assert "iface eth0 inet static" in rewritten
    assert "address 192.168.1.230" in rewritten
    assert "dns-nameservers 127.0.0.1" in rewritten

    # Pi .230 / gateway .1 → the .100-.199 candidate avoids both.
    set_config = dict(fake.posts)["/control/dhcp/set_config"]
    assert set_config == {
        "enabled": True,
        "interface_name": "eth0",
        "v4": {
            "gateway_ip": "192.168.1.1",
            "subnet_mask": "255.255.255.0",
            "range_start": "192.168.1.100",
            "range_end": "192.168.1.199",
            "lease_duration": 86400,
        },
    }


def test_enable_unrecognized_interfaces_file_is_422(authed, monkeypatch, tmp_path):
    test_client, headers = authed
    _wire_route_file(monkeypatch, tmp_path)
    interfaces_file = tmp_path / "interfaces"
    # No eth0 stanza at all (e.g. a NetworkManager-managed system).
    interfaces_file.write_text("auto lo\niface lo inet loopback\n")
    monkeypatch.setattr(dhcp, "INTERFACES_FILE", interfaces_file)
    monkeypatch.setattr(dhcp, "INTERFACES_BACKUP", tmp_path / "interfaces.holdfastbrick-bak")
    fake = FakeAdGuard(
        get_routes={"/control/dhcp/interfaces": ADGUARD_INTERFACES},
        post_routes={
            "/control/dhcp/find_active_dhcp": {
                "v4": {"other_server": {"found": "no"}, "static_ip": {"static": "no"}}
            }
        },
    )
    _wire_fake(monkeypatch, fake)
    resp = test_client.post("/api/v1/dhcp/enable", json={"force": False}, headers=headers)
    assert resp.status_code == 422
    assert "dietpi-config" in resp.json()["detail"]
    assert all(path != "/control/dhcp/set_config" for path, _ in fake.posts)


def test_enable_trusts_user_configured_static_stanza(authed, monkeypatch, tmp_path):
    """A hand-configured `inet static` stanza is trusted even when AdGuard's
    probe claims the IP is dynamic (the probe misreads ifupdown systems)."""
    test_client, headers = authed
    _wire_route_file(monkeypatch, tmp_path)
    interfaces_file = tmp_path / "interfaces"
    original = "iface eth0 inet static\n    address 192.168.1.230\n"
    interfaces_file.write_text(original)
    monkeypatch.setattr(dhcp, "INTERFACES_FILE", interfaces_file)
    monkeypatch.setattr(dhcp, "INTERFACES_BACKUP", tmp_path / "interfaces.holdfastbrick-bak")
    monkeypatch.setattr(dhcp, "_interface_netmask", lambda _: "255.255.255.0")
    fake = FakeAdGuard(
        get_routes={"/control/dhcp/interfaces": ADGUARD_INTERFACES},
        post_routes={
            "/control/dhcp/find_active_dhcp": {
                "v4": {"other_server": {"found": "no"}, "static_ip": {"static": "no"}}
            },
            "/control/dhcp/set_config": "OK.",
        },
    )
    _wire_fake(monkeypatch, fake)
    resp = test_client.post("/api/v1/dhcp/enable", json={"force": False}, headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["needs_reboot"] is False
    assert interfaces_file.read_text() == original  # untouched


def test_enable_static_probe_error_fails_closed_into_pin(authed, monkeypatch, tmp_path):
    """static_ip == "error" must take the pinning path, not skip the guard."""
    test_client, headers = authed
    _wire_route_file(monkeypatch, tmp_path)
    interfaces_file = tmp_path / "interfaces"
    interfaces_file.write_text("auto eth0\niface eth0 inet dhcp\n")
    monkeypatch.setattr(dhcp, "INTERFACES_FILE", interfaces_file)
    monkeypatch.setattr(dhcp, "INTERFACES_BACKUP", tmp_path / "interfaces.holdfastbrick-bak")
    monkeypatch.setattr(dhcp, "_interface_netmask", lambda _: "255.255.255.0")
    fake = FakeAdGuard(
        get_routes={"/control/dhcp/interfaces": ADGUARD_INTERFACES},
        post_routes={
            "/control/dhcp/find_active_dhcp": {
                "v4": {"other_server": {"found": "no"}, "static_ip": {"static": "error"}}
            },
            "/control/dhcp/set_config": "OK.",
        },
    )
    _wire_fake(monkeypatch, fake)
    resp = test_client.post("/api/v1/dhcp/enable", json={"force": False}, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["needs_reboot"] is True
    assert "inet static" in interfaces_file.read_text()
    assert dhcp.PIN_MARKER in interfaces_file.read_text()


def test_enable_already_pinned_stanza_skips_rewrite(authed, monkeypatch, tmp_path):
    """Retry after a failed enable (file already pinned by us) must not 422
    and must not rewrite again."""
    test_client, headers = authed
    _wire_route_file(monkeypatch, tmp_path)
    interfaces_file = tmp_path / "interfaces"
    pinned = (
        f"{dhcp.PIN_MARKER}\n"
        "iface eth0 inet static\n    address 192.168.1.230\n"
    )
    interfaces_file.write_text(pinned)
    monkeypatch.setattr(dhcp, "INTERFACES_FILE", interfaces_file)
    monkeypatch.setattr(dhcp, "INTERFACES_BACKUP", tmp_path / "interfaces.holdfastbrick-bak")
    monkeypatch.setattr(dhcp, "_interface_netmask", lambda _: "255.255.255.0")
    fake = FakeAdGuard(
        get_routes={"/control/dhcp/interfaces": ADGUARD_INTERFACES},
        post_routes={
            "/control/dhcp/find_active_dhcp": {
                "v4": {"other_server": {"found": "no"}, "static_ip": {"static": "no"}}
            },
            "/control/dhcp/set_config": "OK.",
        },
    )
    _wire_fake(monkeypatch, fake)
    resp = test_client.post("/api/v1/dhcp/enable", json={"force": False}, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["needs_reboot"] is True
    assert interfaces_file.read_text() == pinned  # not rewritten again


def test_pick_dhcp_range_respects_small_subnet():
    start, end = dhcp.pick_dhcp_range("192.168.1.230", "192.168.1.193", "255.255.255.192")
    net = __import__("ipaddress").ip_network("192.168.1.192/26")
    for ip in (start, end):
        assert __import__("ipaddress").ip_address(ip) in net
    lo = int(__import__("ipaddress").ip_address(start))
    hi = int(__import__("ipaddress").ip_address(end))
    for occupied in ("192.168.1.230", "192.168.1.193"):
        assert not lo <= int(__import__("ipaddress").ip_address(occupied)) <= hi


# --- /dhcp/disable ------------------------------------------------------------


def test_disable_reposts_config_with_enabled_false(authed, monkeypatch):
    test_client, headers = authed
    fake = FakeAdGuard(
        get_routes={
            "/control/dhcp/status": {
                "enabled": True,
                "interface_name": "eth0",
                "v4": {
                    "gateway_ip": "192.168.1.1",
                    "subnet_mask": "255.255.255.0",
                    "range_start": "192.168.1.100",
                    "range_end": "192.168.1.199",
                    "lease_duration": 86400,
                },
            }
        },
        post_routes={"/control/dhcp/set_config": {}},
    )
    _wire_fake(monkeypatch, fake)
    resp = test_client.post("/api/v1/dhcp/disable", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["ok"] is True
    path, payload = fake.posts[0]
    assert path == "/control/dhcp/set_config"
    assert payload["enabled"] is False
    assert payload["interface_name"] == "eth0"
    assert payload["v4"]["range_start"] == "192.168.1.100"


def test_disable_when_never_configured_still_ok(authed, monkeypatch):
    test_client, headers = authed
    fake = FakeAdGuard(get_routes={"/control/dhcp/status": {"enabled": False}})
    _wire_fake(monkeypatch, fake)
    resp = test_client.post("/api/v1/dhcp/disable", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["ok"] is True
    assert fake.posts == []


def test_netmask_to_prefix():
    assert dhcp.netmask_to_prefix("255.255.255.0") == 24
    assert dhcp.netmask_to_prefix("255.255.255.192") == 26
    assert dhcp.netmask_to_prefix("255.255.0.0") == 16


def _nm_fake_run(calls, connections_stdout):
    from holdfastbrick_api.runner import CommandResult

    async def fake_run(argv, timeout=20.0):
        calls.append(argv)
        if argv[:2] == ["nmcli", "-t"]:
            return CommandResult(ok=True, exit_code=0, stdout=connections_stdout, stderr="")
        return CommandResult(ok=True, exit_code=0, stdout="", stderr="")

    return fake_run


def test_enable_pins_via_networkmanager_when_no_ifupdown(authed, monkeypatch, tmp_path):
    """Raspberry Pi OS: empty interfaces file + NetworkManager-managed
    interface -> pinned via nmcli, needs_reboot, no 422."""
    test_client, headers = authed
    _wire_route_file(monkeypatch, tmp_path)
    interfaces_file = tmp_path / "interfaces"
    interfaces_file.write_text("auto lo\niface lo inet loopback\n")
    monkeypatch.setattr(dhcp, "INTERFACES_FILE", interfaces_file)
    monkeypatch.setattr(dhcp, "INTERFACES_BACKUP", tmp_path / "interfaces.holdfastbrick-bak")
    monkeypatch.setattr(dhcp, "_interface_netmask", lambda _: "255.255.255.0")
    calls: list = []
    monkeypatch.setattr(
        dhcp, "run", _nm_fake_run(calls, "lo:lo\nWired connection 1:eth0\n")
    )
    fake = FakeAdGuard(
        get_routes={"/control/dhcp/interfaces": ADGUARD_INTERFACES},
        post_routes={
            "/control/dhcp/find_active_dhcp": {
                "v4": {"other_server": {"found": "no"}, "static_ip": {"static": "no"}}
            },
            "/control/dhcp/set_config": "OK.",
        },
    )
    _wire_fake(monkeypatch, fake)
    resp = test_client.post("/api/v1/dhcp/enable", json={"force": False}, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["needs_reboot"] is True
    modify = next(c for c in calls if c[:3] == ["nmcli", "connection", "modify"])
    assert "Wired connection 1" in modify
    assert "ipv4.method" in modify and "manual" in modify
    addr_value = modify[modify.index("ipv4.addresses") + 1]
    assert addr_value.endswith("/24")
    assert interfaces_file.read_text() == "auto lo\niface lo inet loopback\n"  # untouched


def test_enable_networkmanager_not_managing_interface_is_422(authed, monkeypatch, tmp_path):
    test_client, headers = authed
    _wire_route_file(monkeypatch, tmp_path)
    interfaces_file = tmp_path / "interfaces"
    interfaces_file.write_text("auto lo\niface lo inet loopback\n")
    monkeypatch.setattr(dhcp, "INTERFACES_FILE", interfaces_file)
    monkeypatch.setattr(dhcp, "INTERFACES_BACKUP", tmp_path / "interfaces.holdfastbrick-bak")
    monkeypatch.setattr(dhcp, "_interface_netmask", lambda _: "255.255.255.0")
    calls: list = []
    monkeypatch.setattr(dhcp, "run", _nm_fake_run(calls, "lo:lo\n"))  # no eth0
    fake = FakeAdGuard(
        get_routes={"/control/dhcp/interfaces": ADGUARD_INTERFACES},
        post_routes={
            "/control/dhcp/find_active_dhcp": {
                "v4": {"other_server": {"found": "no"}, "static_ip": {"static": "no"}}
            }
        },
    )
    _wire_fake(monkeypatch, fake)
    resp = test_client.post("/api/v1/dhcp/enable", json={"force": False}, headers=headers)
    assert resp.status_code == 422
    assert "nmtui" in resp.json()["detail"]
