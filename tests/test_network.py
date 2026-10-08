"""Network reliability: interface classification, static-IP detection and
pinning, DNS probes, the health verdict, and the DHCP WiFi guard."""

from __future__ import annotations

import asyncio
import struct
from datetime import datetime

import pytest

from holdfastbrick_api.runner import CommandError, CommandResult
from holdfastbrick_api.services import dhcp, ipconfig, network, system


# --- helpers -------------------------------------------------------------------


def _wire_route_file(monkeypatch, tmp_path, iface="eth0", gateway_hex="0101A8C0"):
    route = tmp_path / "route"
    route.write_text(
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
        f"{iface}\t00000000\t{gateway_hex}\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
    )
    monkeypatch.setattr(system, "ROUTE_FILE", route)


def _wire_sysfs(monkeypatch, tmp_path, iface, carrier=None, wireless=False):
    base = tmp_path / "sys" / "class" / "net"
    iface_dir = base / iface
    iface_dir.mkdir(parents=True)
    if carrier is not None:
        (iface_dir / "carrier").write_text(f"{int(carrier)}\n")
    if wireless:
        (iface_dir / "wireless").mkdir()
    monkeypatch.setattr(network, "SYS_CLASS_NET", base)


def _wire_interfaces(monkeypatch, tmp_path, content):
    interfaces = tmp_path / "interfaces"
    if content is not None:
        interfaces.write_text(content)
    monkeypatch.setattr(network, "INTERFACES_FILE", interfaces)
    monkeypatch.setattr(network, "INTERFACES_BACKUP", tmp_path / "interfaces.holdfastbrick-bak")
    return interfaces, tmp_path / "interfaces.holdfastbrick-bak"


def _nm_fake_run(*, method_stdout="", pair_stdout="", absent=False):
    """Fake `run` for nmcli queries; the two show commands answer with
    different field counts, so dispatch on the -f value. Returns
    (fake_run, calls)."""
    calls: list[list[str]] = []

    async def fake_run(argv, timeout=20.0):
        calls.append(argv)
        if absent:
            raise CommandError(f"binary not installed: {argv[0]}")
        if argv[:2] == ["nmcli", "-t"] and len(argv) > 3:
            stdout = method_stdout if "ipv4.method" in argv[3] else pair_stdout
            return CommandResult(ok=True, exit_code=0, stdout=stdout, stderr="")
        return CommandResult(ok=True, exit_code=0, stdout="", stderr="")

    return fake_run, calls


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


def _wire_probes(monkeypatch, serving=True, upstream=True):
    probed: list[tuple[str, int, bytes]] = []

    async def fake_probe(host, port, payload, timeout=3.0):
        probed.append((host, port, payload))
        return serving if port == 53 else upstream

    monkeypatch.setattr(network, "probe_dns", fake_probe)
    return probed


def _wire_tunnel(monkeypatch, running=True):
    from holdfastbrick_api.models import ServiceHealth

    async def fake_health():
        return ServiceHealth(
            id="tailscale",
            name="Remote Access",
            running=running,
            detail="Running" if running else "Stopped",
        )

    monkeypatch.setattr(network.tailscale, "health", fake_health)


def _wire_fail_open(monkeypatch, value):
    async def fake():
        return value

    monkeypatch.setattr(network, "_fail_open_check", fake)


def _wire_health_env(
    monkeypatch,
    tmp_path,
    *,
    iface="eth0",
    interfaces_content="iface eth0 inet static\n    address 192.168.1.230\n",
    serving=True,
    upstream=True,
    tunnel_running=True,
):
    _wire_route_file(monkeypatch, tmp_path, iface=iface)
    if iface:
        _wire_sysfs(monkeypatch, tmp_path, iface, carrier=True, wireless=iface.startswith("wl"))
    _wire_interfaces(monkeypatch, tmp_path, interfaces_content)
    _wire_probes(monkeypatch, serving=serving, upstream=upstream)
    _wire_tunnel(monkeypatch, running=tunnel_running)
    _wire_fail_open(monkeypatch, True)


def _qname(payload: bytes) -> str:
    labels = []
    i = 12
    while payload[i] != 0:
        length = payload[i]
        labels.append(payload[i + 1 : i + 1 + length].decode())
        i += 1 + length
    return ".".join(labels)


# --- auth gating -----------------------------------------------------------------


def test_network_endpoints_require_token(client):
    test_client, _ = client
    assert test_client.get("/api/v1/network/status").status_code == 401
    assert test_client.post("/api/v1/network/pin-ip").status_code == 401
    assert test_client.get("/api/v1/network/health").status_code == 401


# --- classify_interface / is_wifi / read_carrier ---------------------------------


@pytest.mark.parametrize(
    ("name", "has_wireless", "expected"),
    [
        ("wlan0", False, "wifi"),
        ("wlx00c0cafe", False, "wifi"),
        ("wlp3s0", False, "wifi"),
        ("eth0", False, "ethernet"),
        ("eth1", False, "ethernet"),
        ("enp3s0", False, "ethernet"),
        ("eno1", False, "ethernet"),
        ("ens5", False, "ethernet"),
        ("end0", False, "ethernet"),
        ("usp0", False, "ethernet"),
        ("lo", False, "unknown"),
        ("tun0", False, "unknown"),
        ("br0", False, "unknown"),
        ("uplink0", True, "wifi"),
        ("uplink0", False, "unknown"),
    ],
)
def test_classify_interface_table(name, has_wireless, expected):
    assert network.classify_interface(name, has_wireless) == expected


def test_is_wifi_uses_kernel_wireless_ext(monkeypatch, tmp_path):
    base = tmp_path / "net"
    (base / "uplink0" / "wireless").mkdir(parents=True)
    (base / "eth0").mkdir()
    monkeypatch.setattr(ipconfig, "SYS_CLASS_NET", base)
    assert ipconfig.is_wifi("uplink0") is True  # kernel confirms wireless
    assert ipconfig.is_wifi("eth0") is False  # known ethernet prefix wins
    assert ipconfig.is_wifi("wlan0") is True  # name prefix alone


def test_read_carrier_from_sysfs(monkeypatch, tmp_path):
    base = tmp_path / "net"
    up = base / "eth0"
    up.mkdir(parents=True)
    (up / "carrier").write_text("1\n")
    down = base / "eth1"
    down.mkdir(parents=True)
    (down / "carrier").write_text("0")
    silent = base / "eth2"
    silent.mkdir(parents=True)
    monkeypatch.setattr(network, "SYS_CLASS_NET", base)
    assert network.read_carrier("eth0") is True
    assert network.read_carrier("eth1") is False
    assert network.read_carrier("eth2") is None  # interface without a carrier file
    assert network.read_carrier("missing") is None  # no interface at all


def test_ethernet_check_matrix():
    assert network.ethernet_check("ethernet", True)["status"] == "pass"
    unplugged = network.ethernet_check("ethernet", False)
    assert unplugged["status"] == "fail"
    assert "unplugged" in unplugged["detail"]
    wifi = network.ethernet_check("wifi", True)
    assert wifi["status"] == "warn"
    assert wifi["detail"] == network._WIFI_WARNING
    # Unknown connection with no carrier reading cannot be verified.
    assert network.ethernet_check("unknown", None)["status"] == "fail"
    assert network.ethernet_check("unknown", True)["status"] == "warn"
    assert network.ethernet_check("ethernet", None)["status"] == "warn"


# --- detect_static_ip --------------------------------------------------------------


async def test_detect_static_ip_matrix(monkeypatch, tmp_path):
    interfaces, _backup = _wire_interfaces(monkeypatch, tmp_path, None)

    interfaces.write_text("iface eth0 inet static\n    address 192.168.1.230\n")
    assert await network.detect_static_ip("eth0") == (True, "ifupdown")

    interfaces.write_text(f"{ipconfig.PIN_MARKER}\niface eth0 inet static\n")
    assert await network.detect_static_ip("eth0") == (True, "ifupdown")

    interfaces.write_text("iface eth0 inet dhcp\n")
    assert await network.detect_static_ip("eth0") == (False, "ifupdown")

    interfaces.write_text("auto lo\niface lo inet loopback\n")
    run_show, _ = _nm_fake_run(method_stdout="Wired connection 1:eth0:manual")
    monkeypatch.setattr(network, "run", run_show)
    assert await network.detect_static_ip("eth0") == (True, "networkmanager")

    run_dhcp, _ = _nm_fake_run(method_stdout="Wired connection 1:eth0:dhcp")
    monkeypatch.setattr(network, "run", run_dhcp)
    assert await network.detect_static_ip("eth0") == (False, "networkmanager")

    run_absent, _ = _nm_fake_run(absent=True)
    monkeypatch.setattr(network, "run", run_absent)
    assert await network.detect_static_ip("eth0") == (None, "unknown")
    assert await network.detect_static_ip(None) == (None, "unknown")


# --- /network/status ---------------------------------------------------------------


def test_status_reports_wired_static(authed, monkeypatch, tmp_path):
    test_client, headers = authed
    _wire_route_file(monkeypatch, tmp_path)
    _wire_sysfs(monkeypatch, tmp_path, "eth0", carrier=True)
    monkeypatch.setattr(network, "_interface_ip", lambda iface: "192.168.1.230")
    _wire_interfaces(monkeypatch, tmp_path, "iface eth0 inet static\n    address 192.168.1.230\n")

    resp = test_client.get("/api/v1/network/status", headers=headers)
    assert resp.status_code == 200
    assert resp.json() == {
        "interface": "eth0",
        "connection": "ethernet",
        "carrier": True,
        "ip": "192.168.1.230",
        "gateway": "192.168.1.1",
        "static_ip": True,
        "managed_by": "ifupdown",
    }


def test_status_reports_wifi_with_dhcp_address(authed, monkeypatch, tmp_path):
    test_client, headers = authed
    _wire_route_file(monkeypatch, tmp_path, iface="wlan0")
    _wire_sysfs(monkeypatch, tmp_path, "wlan0", carrier=None, wireless=True)
    monkeypatch.setattr(network, "_interface_ip", lambda iface: "192.168.1.77")
    _wire_interfaces(monkeypatch, tmp_path, "iface wlan0 inet dhcp\n")

    resp = test_client.get("/api/v1/network/status", headers=headers)
    assert resp.status_code == 200
    assert resp.json() == {
        "interface": "wlan0",
        "connection": "wifi",
        "carrier": None,
        "ip": "192.168.1.77",
        "gateway": "192.168.1.1",
        "static_ip": False,
        "managed_by": "ifupdown",
    }


def test_status_nmcli_absent_is_unknown(authed, monkeypatch, tmp_path):
    test_client, headers = authed
    _wire_route_file(monkeypatch, tmp_path)
    monkeypatch.setattr(network, "_interface_ip", lambda iface: "192.168.1.230")
    _wire_interfaces(monkeypatch, tmp_path, None)  # no ifupdown file at all
    run_absent, _ = _nm_fake_run(absent=True)
    monkeypatch.setattr(network, "run", run_absent)

    resp = test_client.get("/api/v1/network/status", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["static_ip"] is None
    assert body["managed_by"] == "unknown"


def test_status_nm_manual_is_static(authed, monkeypatch, tmp_path):
    test_client, headers = authed
    _wire_route_file(monkeypatch, tmp_path)
    monkeypatch.setattr(network, "_interface_ip", lambda iface: "192.168.1.230")
    _wire_interfaces(monkeypatch, tmp_path, None)
    run_show, _ = _nm_fake_run(method_stdout="Wired connection 1:eth0:manual")
    monkeypatch.setattr(network, "run", run_show)

    resp = test_client.get("/api/v1/network/status", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["static_ip"] is True
    assert body["managed_by"] == "networkmanager"


# --- /network/pin-ip ----------------------------------------------------------------


def test_pin_ip_rewrites_dhcp_stanza_and_backs_up(authed, monkeypatch, tmp_path):
    test_client, headers = authed
    _wire_route_file(monkeypatch, tmp_path)
    monkeypatch.setattr(network, "_interface_ip", lambda iface: "192.168.1.230")
    monkeypatch.setattr(network, "_interface_netmask", lambda iface: "255.255.255.0")
    original = (
        "# interfaces(5) file used by ifup(8) and ifdown(8)\n"
        "auto lo\niface lo inet loopback\n\nallow-hotplug eth0\niface eth0 inet dhcp\n"
    )
    interfaces, backup = _wire_interfaces(monkeypatch, tmp_path, original)

    resp = test_client.post("/api/v1/network/pin-ip", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["needs_reboot"] is True
    assert "reboot" in body["message"].lower()

    assert backup.read_text() == original
    rewritten = interfaces.read_text()
    assert "iface eth0 inet static" in rewritten
    assert "address 192.168.1.230" in rewritten
    assert "netmask 255.255.255.0" in rewritten
    assert "gateway 192.168.1.1" in rewritten
    assert ipconfig.PIN_MARKER in rewritten


def test_pin_ip_already_static_is_idempotent(authed, monkeypatch, tmp_path):
    test_client, headers = authed
    _wire_route_file(monkeypatch, tmp_path)
    monkeypatch.setattr(network, "_interface_ip", lambda iface: "192.168.1.230")
    original = "iface eth0 inet static\n    address 192.168.1.230\n"
    interfaces, backup = _wire_interfaces(monkeypatch, tmp_path, original)

    resp = test_client.post("/api/v1/network/pin-ip", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["needs_reboot"] is False
    assert "already static" in body["message"]
    assert interfaces.read_text() == original  # untouched
    assert not backup.exists()  # nothing written at all


def test_pin_ip_pins_via_networkmanager(authed, monkeypatch, tmp_path):
    test_client, headers = authed
    _wire_route_file(monkeypatch, tmp_path)
    monkeypatch.setattr(network, "_interface_ip", lambda iface: "192.168.1.230")
    monkeypatch.setattr(network, "_interface_netmask", lambda iface: "255.255.255.0")
    interfaces, _backup = _wire_interfaces(monkeypatch, tmp_path, None)  # no ifupdown file
    net_run, _ = _nm_fake_run(method_stdout="Wired connection 1:eth0:dhcp")
    monkeypatch.setattr(network, "run", net_run)
    nm_run, dhcp_calls = _nm_fake_run(pair_stdout="Wired connection 1:eth0")
    # The NM pin primitive lives in ipconfig now, so its `run` resolves there.
    monkeypatch.setattr(ipconfig, "run", nm_run)

    resp = test_client.post("/api/v1/network/pin-ip", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["needs_reboot"] is True

    modify = next(c for c in dhcp_calls if c[:3] == ["nmcli", "connection", "modify"])
    assert "Wired connection 1" in modify
    assert modify[modify.index("ipv4.method") + 1] == "manual"
    assert modify[modify.index("ipv4.addresses") + 1] == "192.168.1.230/24"
    assert modify[modify.index("ipv4.gateway") + 1] == "192.168.1.1"
    assert not interfaces.exists()  # the ifupdown file is never touched


def test_pin_ip_nm_manual_already_is_idempotent(authed, monkeypatch, tmp_path):
    test_client, headers = authed
    _wire_route_file(monkeypatch, tmp_path)
    monkeypatch.setattr(network, "_interface_ip", lambda iface: "192.168.1.230")
    _wire_interfaces(monkeypatch, tmp_path, None)
    net_run, _ = _nm_fake_run(method_stdout="Wired connection 1:eth0:manual")
    monkeypatch.setattr(network, "run", net_run)
    nm_run, dhcp_calls = _nm_fake_run(pair_stdout="Wired connection 1:eth0")
    # The NM pin primitive lives in ipconfig now, so its `run` resolves there.
    monkeypatch.setattr(ipconfig, "run", nm_run)

    resp = test_client.post("/api/v1/network/pin-ip", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["needs_reboot"] is False
    assert "already static" in body["message"]
    assert all(c[:3] != ["nmcli", "connection", "modify"] for c in dhcp_calls)


def test_pin_ip_dead_end_is_422_with_hint(authed, monkeypatch, tmp_path):
    test_client, headers = authed
    _wire_route_file(monkeypatch, tmp_path)
    monkeypatch.setattr(network, "_interface_ip", lambda iface: "192.168.1.230")
    monkeypatch.setattr(network, "_interface_netmask", lambda iface: "255.255.255.0")
    interfaces, backup = _wire_interfaces(monkeypatch, tmp_path, None)
    net_run, _ = _nm_fake_run(absent=True)
    monkeypatch.setattr(network, "run", net_run)
    nm_run, _ = _nm_fake_run(absent=True)
    monkeypatch.setattr(ipconfig, "run", nm_run)

    resp = test_client.post("/api/v1/network/pin-ip", headers=headers)
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert "dietpi-config" in detail
    assert "nmtui" in detail
    assert not interfaces.exists()
    assert not backup.exists()


def test_pin_ip_without_default_route_is_422(authed, monkeypatch, tmp_path):
    test_client, headers = authed
    route = tmp_path / "route"
    route.write_text(
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n"
        "eth0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\n"
    )
    monkeypatch.setattr(system, "ROUTE_FILE", route)

    resp = test_client.post("/api/v1/network/pin-ip", headers=headers)
    assert resp.status_code == 422
    assert "interface" in resp.json()["detail"]


# --- DNS probes ----------------------------------------------------------------------


def test_build_dns_query_structure():
    packet = network.build_dns_query("example.com", txid=0xABCD)
    txid, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", packet[:12])
    assert txid == 0xABCD
    assert flags & 0x8000 == 0  # qr=0: a query, not a response
    assert qdcount == 1
    assert ancount == nscount == arcount == 0
    labels = []
    i = 12
    while packet[i] != 0:
        length = packet[i]
        labels.append(packet[i + 1 : i + 1 + length].decode())
        i += 1 + length
    i += 1  # root label
    assert labels == ["example", "com"]
    qtype, qclass = struct.unpack(">HH", packet[i : i + 4])
    assert qtype == 1  # A
    assert qclass == 1  # IN
    assert len(packet) == i + 4
    assert network.build_dns_query("example.com.", txid=0xABCD) == packet  # trailing dot optional


async def test_probe_dns_true_when_server_answers():
    async def handle(reader, writer):
        data = await reader.read(1024)
        if len(data) > 5:
            # Real-reply shape: same transaction id, QR bit set, length-prefixed.
            msg = data[2:]
            reply = msg[:2] + bytes([msg[2] | 0x80]) + msg[3:]
            writer.write(struct.pack(">H", len(reply)) + reply)
            await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        query = network.build_dns_query("example.com", txid=0x4242)
        assert await network.probe_dns("127.0.0.1", port, query, timeout=2.0) is True
    finally:
        server.close()
        await server.wait_closed()


async def test_probe_dns_false_when_connection_refused():
    query = network.build_dns_query("example.com")
    assert await network.probe_dns("127.0.0.1", 1, query, timeout=1.0) is False


# --- compose_verdict -------------------------------------------------------------------


def _checks(serving="pass", upstream="pass", static="pass"):
    return {
        "dns_serving": {"status": serving, "detail": ""},
        "upstream_dns": {"status": upstream, "detail": ""},
        "static_ip": {"status": static, "detail": ""},
    }


def test_compose_verdict_truth_table():
    assert network.compose_verdict(_checks(), "ethernet") == "protected"
    assert network.compose_verdict(_checks(), "unknown") == "protected"

    # dns_serving fail is "down", whatever else says.
    unplugged = _checks()
    unplugged["ethernet"] = {"status": "fail", "detail": "cable"}
    assert network.compose_verdict(unplugged, "ethernet") == "down"
    assert network.compose_verdict(_checks(serving="fail"), "ethernet") == "down"
    assert network.compose_verdict(_checks(serving="fail"), "wifi") == "down"
    assert network.compose_verdict(_checks(serving="fail", upstream="fail"), "ethernet") == "down"

    # Serving but no upstream: at risk (stale answers, then unfiltered).
    assert network.compose_verdict(_checks(upstream="fail"), "ethernet") == "at_risk"

    # Real probes never produce a warn for serving; per the verdict rules a
    # synthetic warn with no fails and no wifi stays "protected".
    assert network.compose_verdict(_checks(serving="warn"), "ethernet") == "protected"

    # A dhcp-assigned IP caps the verdict at at_risk.
    assert network.compose_verdict(_checks(static="fail"), "ethernet") == "at_risk"
    assert network.compose_verdict(_checks(static="warn"), "ethernet") == "protected"

    # WiFi caps at at_risk too, and never upgrades "down".
    assert network.compose_verdict(_checks(), "wifi") == "at_risk"
    assert network.compose_verdict(_checks(static="fail"), "wifi") == "at_risk"

    # Every combination of statuses × connection, against the rules.
    for serving in ("pass", "warn", "fail"):
        for upstream in ("pass", "warn", "fail"):
            for static in ("pass", "warn", "fail"):
                for connection in ("ethernet", "wifi", "unknown"):
                    if serving == "fail":
                        expected = "down"
                    elif upstream == "fail" or static == "fail" or connection == "wifi":
                        expected = "at_risk"
                    else:
                        expected = "protected"
                    checks = _checks(serving=serving, upstream=upstream, static=static)
                    assert network.compose_verdict(checks, connection) == expected


# --- /network/health -------------------------------------------------------------------


def test_health_all_pass_is_protected(authed, monkeypatch, tmp_path):
    test_client, headers = authed
    _wire_health_env(monkeypatch, tmp_path)
    probed = _wire_probes(monkeypatch)  # re-wire to capture payloads

    resp = test_client.get("/api/v1/network/health", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["overall"] == "protected"
    assert set(body["checks"]) == {
        "ethernet",
        "static_ip",
        "dns_serving",
        "upstream_dns",
        "tunnel",
    }
    assert all(c["status"] == "pass" for c in body["checks"].values())
    assert body["warnings"] == []
    assert body["fail_open"] == {"router_secondary_possible": True}
    datetime.fromisoformat(body["checked_at"])

    by_port = {port: payload for _host, port, payload in probed}
    assert 53 in by_port and 5335 in by_port
    assert _qname(by_port[53]) == "probe.holdfast"
    assert _qname(by_port[5335]) == "example.com"


def test_health_serving_fail_is_down(authed, monkeypatch, tmp_path):
    test_client, headers = authed
    _wire_health_env(monkeypatch, tmp_path, serving=False)

    body = test_client.get("/api/v1/network/health", headers=headers).json()
    assert body["overall"] == "down"
    assert body["checks"]["dns_serving"]["status"] == "fail"
    assert body["checks"]["dns_serving"]["detail"] in body["warnings"]


def test_health_upstream_fail_is_at_risk(authed, monkeypatch, tmp_path):
    test_client, headers = authed
    _wire_health_env(monkeypatch, tmp_path, upstream=False)

    body = test_client.get("/api/v1/network/health", headers=headers).json()
    assert body["overall"] == "at_risk"
    assert body["checks"]["dns_serving"]["status"] == "pass"
    assert body["checks"]["upstream_dns"]["status"] == "fail"
    assert body["checks"]["upstream_dns"]["detail"] in body["warnings"]


def test_health_dhcp_ip_caps_at_risk(authed, monkeypatch, tmp_path):
    test_client, headers = authed
    _wire_health_env(
        monkeypatch, tmp_path, interfaces_content="iface eth0 inet dhcp\n"
    )

    body = test_client.get("/api/v1/network/health", headers=headers).json()
    assert body["overall"] == "at_risk"
    assert body["checks"]["static_ip"]["status"] == "fail"
    assert body["checks"]["static_ip"]["detail"] in body["warnings"]


def test_health_wifi_caps_at_risk_with_warning(authed, monkeypatch, tmp_path):
    test_client, headers = authed
    _wire_health_env(monkeypatch, tmp_path, iface="wlan0")

    body = test_client.get("/api/v1/network/health", headers=headers).json()
    assert body["overall"] == "at_risk"
    assert body["checks"]["ethernet"]["status"] == "warn"
    assert network._WIFI_WARNING in body["warnings"]


def test_health_tunnel_down_warns_but_stays_protected(authed, monkeypatch, tmp_path):
    test_client, headers = authed
    _wire_health_env(monkeypatch, tmp_path, tunnel_running=False)

    body = test_client.get("/api/v1/network/health", headers=headers).json()
    assert body["overall"] == "protected"
    assert body["checks"]["tunnel"]["status"] == "warn"
    assert body["checks"]["tunnel"]["detail"] in body["warnings"]


def test_health_unplugged_cable_is_down_even_with_local_dns_ok(
    authed, monkeypatch, tmp_path
):
    """A loopback DNS probe can pass while no household device can reach the
    brick — the unplugged-cable fail must gate the verdict (peer review)."""
    test_client, headers = authed
    _wire_route_file(monkeypatch, tmp_path, iface="eth0")
    _wire_sysfs(monkeypatch, tmp_path, "eth0", carrier=False, wireless=False)
    _wire_interfaces(
        monkeypatch, tmp_path, "iface eth0 inet static\n    address 192.168.1.230\n"
    )
    _wire_probes(monkeypatch, serving=True, upstream=True)
    _wire_tunnel(monkeypatch, running=True)
    _wire_fail_open(monkeypatch, True)

    body = test_client.get("/api/v1/network/health", headers=headers).json()
    assert body["overall"] == "down"
    assert body["checks"]["ethernet"]["status"] == "fail"
    assert body["checks"]["dns_serving"]["status"] == "pass"


def test_health_fail_open_follows_adguard_dhcp(authed, monkeypatch, tmp_path):
    test_client, headers = authed
    real_fail_open = network._fail_open_check
    _wire_health_env(monkeypatch, tmp_path)
    monkeypatch.setattr(network, "_fail_open_check", real_fail_open)  # the thing under test
    real_client = network._client

    monkeypatch.setattr(
        network,
        "_client",
        lambda: FakeAdGuard(get_routes={"/control/dhcp/status": {"enabled": False}}),
    )
    body = test_client.get("/api/v1/network/health", headers=headers).json()
    assert body["fail_open"] == {"router_secondary_possible": True}

    monkeypatch.setattr(
        network,
        "_client",
        lambda: FakeAdGuard(get_routes={"/control/dhcp/status": {"enabled": True}}),
    )
    body = test_client.get("/api/v1/network/health", headers=headers).json()
    assert body["fail_open"] == {"router_secondary_possible": False}

    # AdGuard unreachable in the test environment: unknown, never an error.
    monkeypatch.setattr(network, "_client", real_client)
    body = test_client.get("/api/v1/network/health", headers=headers).json()
    assert body["fail_open"] == {"router_secondary_possible": None}


# --- DHCP takeover WiFi guard -----------------------------------------------------------


def test_enable_over_wifi_is_409_before_any_adguard_call(authed, monkeypatch, tmp_path):
    test_client, headers = authed
    _wire_route_file(monkeypatch, tmp_path, iface="wlan0")
    fake = FakeAdGuard()  # any AdGuard access would raise: the guard must fire first
    monkeypatch.setattr(dhcp, "_client", lambda: fake)

    for force in (False, True):
        resp = test_client.post("/api/v1/dhcp/enable", json={"force": force}, headers=headers)
        assert resp.status_code == 409
        assert "wired connection" in resp.json()["detail"]
    assert fake.posts == []
