"""Network reliability: connection status, standalone static-IP pinning, and
the aggregated connection-health verdict.

The brick sits in front of household DNS, so its own reachability is the
household's single point of failure. /network/health reports on that
honestly: what is broken, what is merely at risk, and when the household is
silently falling back to unfiltered DNS.

Fail-open DNS (requirements doc #17) is a router-side setting: in default
mode the router keeps DHCP and lists the brick as primary resolver with
itself as secondary, so brick loss degrades to unfiltered internet instead
of no internet. This API can only verify the brick's side of that deal
(that the brick is not running the household's DHCP); whether the router's
own DNS list is ordered that way is a manual check, stated plainly in the
app. Static-IP pinning here is standalone: it never depends on AdGuard and
never touches DHCP takeover.
"""

from __future__ import annotations

import asyncio
import fcntl
import secrets
import re
import socket
import struct
from datetime import datetime, timezone
from pathlib import Path

import httpx
from fastapi import APIRouter, Depends, HTTPException

from ..auth import require_token
from ..config import settings
from ..runner import CommandError, run
from . import tailscale
from .adguard import _client
from .ipconfig import (
    INTERFACES_BACKUP,
    INTERFACES_FILE,
    _STATIC_IP_HINT,
    _interface_netmask,
    _pin_static_via_networkmanager,
    _write_atomic,
    classify_interface,
    has_wireless_ext,
    interfaces_static_state,
    rewrite_interfaces_static,
)
from .system import read_default_route

router = APIRouter(prefix="/network", tags=["network"], dependencies=[Depends(require_token)])

SYS_CLASS_NET = Path("/sys/class/net")

SIOCGIFADDR = 0x8915  # Linux ioctl: get interface address

_DNS_PROBE_TIMEOUT = 3.0
# Any name works for the serving probe (even NXDOMAIN proves the server
# answers); the upstream probe uses a stable public name so a stale or
# poisoned answer can't masquerade as a local-blocked domain.
DNS_PROBE_NAME_SERVING = "probe.holdfast"
DNS_PROBE_NAME_UPSTREAM = "example.com"

_WIFI_WARNING = (
    "The brick is on WiFi. It works, but WiFi drops are the most common way a "
    "whole household loses the internet at once. Move the brick to a wired "
    "port on your router when you can."
)
_SERVING_PASS = "The brick is answering DNS requests for your network."
_SERVING_FAIL = (
    "The brick isn't answering DNS requests. Devices keep working off cached "
    "answers for a while, then lose the internet."
)
_UPSTREAM_PASS = "The brick can reach its own upstream resolver."
_UPSTREAM_FAIL = (
    "The brick can't reach its own upstream DNS. Cached answers keep browsing "
    "working for a while; once they expire, browsing breaks or falls back to "
    "your router, unfiltered."
)


# --- interface classification (pure logic + read-only /sys checks) -----------

def read_carrier(iface: str) -> bool | None:
    """Link carrier from /sys; None when the file or interface is absent.

    A wired interface reporting False means the cable is unplugged."""
    try:
        value = (SYS_CLASS_NET / iface / "carrier").read_text().strip()
    except OSError:
        return None
    return value == "1"


def _interface_ip(iface: str) -> str | None:
    """IPv4 address of ``iface`` via the SIOCGIFADDR ioctl; None when absent."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            packed = fcntl.ioctl(
                sock.fileno(),
                SIOCGIFADDR,
                struct.pack("256s", iface.encode()[:15]),
            )
        return socket.inet_ntoa(packed[20:24])
    except OSError:
        return None


# --- static-IP detection ------------------------------------------------------

async def _nm_connection_method(iface: str) -> tuple[str | None, str | None]:
    """(connection name, ipv4.method) of the active NetworkManager connection
    on ``iface``; (None, None) when nmcli is absent, fails, or nothing matches."""
    try:
        result = await run(
            ["nmcli", "-t", "-f", "NAME,DEVICE,ipv4.method", "connection", "show", "--active"]
        )
    except CommandError:
        return None, None
    if not result.ok:
        return None, None
    for line in result.stdout.splitlines():
        # Terse mode separates with ':'; literal colons in names arrive as '\:'.
        parts = re.split(r"(?<!\\):", line.strip())
        if len(parts) >= 3 and parts[1] == iface:
            return parts[0].replace("\\:", ":"), parts[2]
    return None, None


async def detect_static_ip(iface: str | None) -> tuple[bool | None, str]:
    """(static_ip, managed_by) for ``iface``.

    The ifupdown file is the authority when it carries a stanza for the
    interface; otherwise NetworkManager's active connection decides. A None
    static_ip with managed_by "unknown" means we simply can't tell.
    """
    if not iface:
        return None, "unknown"
    try:
        content = INTERFACES_FILE.read_text()
    except OSError:
        content = ""
    state = interfaces_static_state(content, iface)
    if state in ("static", "pinned"):
        return True, "ifupdown"
    if state == "dhcp":
        return False, "ifupdown"
    _conn, method = await _nm_connection_method(iface)
    if method is not None:
        return method == "manual", "networkmanager"
    return None, "unknown"


# --- DNS probes ----------------------------------------------------------------

def build_dns_query(name: str, txid: int | None = None) -> bytes:
    """Minimal DNS A-query packet: 12-byte header (id, RD, qdcount=1) +
    QNAME labels + QTYPE=A/QCLASS=IN. A fresh random transaction id per
    probe unless the caller pins one."""
    if txid is None:
        txid = secrets.randbits(16)
    labels = name.rstrip(".").split(".")
    qname = b"".join(bytes([len(label)]) + label.encode() for label in labels) + b"\x00"
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    return header + qname + struct.pack(">HH", 1, 1)


async def probe_dns(host: str, port: int, payload: bytes, timeout: float = 3.0) -> bool:
    """True when a DNS server at host:port answers ``payload``.

    Transport is TCP (asyncio.open_connection) with the RFC 1035 2-byte
    length prefix; AdGuard and Unbound both listen on TCP as well as UDP.
    The reply must echo our transaction id in its header and carry the QR
    bit, NXDOMAIN included: the question is whether the server answers,
    not what it says. A timeout or refused connection counts as down."""
    txid = payload[:2]
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except (OSError, asyncio.TimeoutError):
        return False
    try:
        writer.write(struct.pack(">H", len(payload)) + payload)
        await asyncio.wait_for(writer.drain(), timeout)

        async def read_exact(n: int) -> bytes | None:
            data = b""
            while len(data) < n:
                chunk = await asyncio.wait_for(reader.read(n - len(data)), timeout)
                if not chunk:
                    return None
                data += chunk
            return data

        head = await read_exact(2)
        if head is None:
            return False
        (length,) = struct.unpack(">H", head)
        body = await read_exact(length) if length else b""
    except (OSError, asyncio.TimeoutError):
        return False
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
    # body is the DNS message: id echoes ours, QR bit set, flags present.
    return len(body) >= 4 and body[:2] == txid and bool(body[2] & 0x80)


async def _dns_probe_check(
    host: str, port: int, name: str, pass_detail: str, fail_detail: str
) -> dict:
    try:
        answered = await probe_dns(
            host, port, build_dns_query(name), timeout=_DNS_PROBE_TIMEOUT
        )
    except Exception:  # a probe bug must never leak into the health response
        answered = False
    return {
        "status": "pass" if answered else "fail",
        "detail": pass_detail if answered else fail_detail,
    }


# --- health verdict (pure logic) ------------------------------------------------

def ethernet_check(connection: str, carrier: bool | None) -> dict:
    """The wired-link check. WiFi is a warn (reliability, never silence);
    an unidentifiable connection with no carrier reading is a fail; a wired
    port reporting no carrier means the cable is unplugged."""
    if connection == "wifi":
        return {"status": "warn", "detail": _WIFI_WARNING}
    if connection == "unknown" and carrier is None:
        return {
            "status": "fail",
            "detail": "Couldn't confirm the brick's network connection. Make sure the cable to your router is plugged in on both ends.",
        }
    if carrier is False:
        return {
            "status": "fail",
            "detail": "The network cable is unplugged. Plug the brick into a wired port on your router.",
        }
    if connection == "unknown" or carrier is None:
        return {
            "status": "warn",
            "detail": "Couldn't confirm how the brick is connected to the network. If the brick is online, this is safe to ignore.",
        }
    return {"status": "pass", "detail": "The brick is wired to your router."}


def compose_verdict(checks: dict, connection: str) -> str:
    """Household verdict from the check statuses.

    dns_serving fail or an unplugged/down interface is "down": household
    resolution itself is dark (a loopback probe can pass while no household
    device can reach the brick, so the ethernet check gates the verdict).
    Serving but no upstream is "at_risk": answers may be stale, unfiltered
    once the cache expires. A dhcp-assigned IP or a WiFi connection caps
    the verdict at "at_risk" (the brick's own reliability). Otherwise
    "protected".
    """

    def status(name: str) -> str:
        return (checks.get(name) or {}).get("status", "warn")

    if status("dns_serving") == "fail" or status("ethernet") == "fail":
        return "down"
    if status("upstream_dns") == "fail":
        return "at_risk"
    if status("static_ip") == "fail" or connection == "wifi":
        return "at_risk"
    return "protected"


# --- per-check helpers -----------------------------------------------------------

async def _static_ip_check(iface: str | None) -> dict:
    static, _managed_by = await detect_static_ip(iface)
    if static is True:
        return {
            "status": "pass",
            "detail": "The brick's IP address is static, so your household can always find it.",
        }
    if static is False:
        return {
            "status": "fail",
            "detail": (
                "The brick's IP address is handed out by DHCP. A reboot or router "
                "change could move it and take the household's filtering down with "
                "it. Pin it static from the Network screen."
            ),
        }
    return {
        "status": "warn",
        "detail": "Couldn't confirm whether the brick's IP address is static.",
    }


async def _tunnel_check() -> dict:
    health = await tailscale.health()
    if health.running:
        if settings.headscale_url:
            return {"status": "pass", "detail": "Remote access is up."}
        return {
            "status": "pass",
            "detail": "Remote access is up. Household enrollment isn't configured on this brick, so new phones can't join yet.",
        }
    return {
        "status": "warn",
        "detail": "Remote access is down. The brick still filters your household at home; you just can't reach it while away.",
    }


async def _fail_open_check() -> bool | None:
    """Brick-side approximation of fail-open DNS (requirements doc #17).

    True when the brick is NOT the household's DHCP server: the router can
    then keep DHCP with the brick as primary resolver and itself as
    secondary, so brick loss degrades to unfiltered internet. Whether the
    router's DNS list is actually ordered that way is a manual check on the
    router. None when AdGuard is unreachable and the answer is unknown."""
    try:
        async with _client() as client:
            resp = await client.get("/control/dhcp/status")
            resp.raise_for_status()
            enabled = bool((resp.json() or {}).get("enabled", False))
    except (httpx.HTTPError, ValueError, AttributeError):
        # Non-JSON body or a JSON non-object: unknown, not an error page 500.
        return None
    return not enabled


# --- endpoints ----------------------------------------------------------------

@router.get("/status")
async def get_status() -> dict:
    """How the brick is connected: interface, connection type, cable state,
    addresses, and whether its IP is static (and what manages it)."""
    route = read_default_route()
    iface = route[0] if route else None
    gateway = route[1] if route else None
    connection = classify_interface(iface, has_wireless_ext(iface)) if iface else "unknown"
    carrier = read_carrier(iface) if iface else None
    ip = _interface_ip(iface) if iface else None
    static_ip, managed_by = await detect_static_ip(iface)
    return {
        "interface": iface,
        "connection": connection,
        "carrier": carrier,
        "ip": ip,
        "gateway": gateway,
        "static_ip": static_ip,
        "managed_by": managed_by,
    }


_ALREADY_STATIC = "The brick's IP is already static. Nothing to do."
_REBOOT_NOTE = "Reboot the brick to finish."


@router.post("/pin-ip")
async def pin_ip() -> dict:
    """Pin the brick's CURRENT IP as static, standalone.

    No AdGuard dependency, no DHCP takeover: this only makes the brick's own
    address survive reboots and router changes so the household can always
    find it. Idempotent. Every value is computed before the first write, so
    a failure can never leave a half-applied config behind."""
    route = read_default_route()
    if not route:
        raise HTTPException(
            status_code=422,
            detail="Couldn't find the brick's network interface. Is the cable to your router plugged in?",
        )
    iface, gateway = route
    ip = _interface_ip(iface)
    if not ip:
        raise HTTPException(
            status_code=422,
            detail="Couldn't read the brick's current IP address.",
        )
    netmask = _interface_netmask(iface)
    try:
        content = INTERFACES_FILE.read_text()
    except OSError:
        content = ""
    state = interfaces_static_state(content, iface)

    if state == "pinned":
        # A previous pin already rewrote the file, but until the brick
        # reboots the address can still churn — the reboot requirement
        # stands (same reasoning as the pinned path in dhcp/enable).
        return {
            "ok": True,
            "needs_reboot": True,
            "message": f"The brick's IP is already pinned static. {_REBOOT_NOTE}",
        }
    if state == "static":
        return {"ok": True, "needs_reboot": False, "message": _ALREADY_STATIC}
    if state == "unrecognized":
        _conn, method = await _nm_connection_method(iface)
        if method == "manual":
            return {"ok": True, "needs_reboot": False, "message": _ALREADY_STATIC}
        if await _pin_static_via_networkmanager(iface, ip, netmask, gateway):
            return {
                "ok": True,
                "needs_reboot": True,
                "message": f"The brick's IP is pinned static through NetworkManager. {_REBOOT_NOTE}",
            }
        raise HTTPException(status_code=422, detail=_STATIC_IP_HINT)

    rewritten = rewrite_interfaces_static(content, iface, ip, netmask, gateway)
    _write_atomic(INTERFACES_BACKUP, content)
    _write_atomic(INTERFACES_FILE, rewritten)
    return {
        "ok": True,
        "needs_reboot": True,
        "message": f"The brick's IP is pinned static. {_REBOOT_NOTE}",
    }


@router.get("/health")
async def get_health() -> dict:
    """Aggregated connection-health verdict for the brick's side of the
    household DNS chain. ``overall`` comes from compose_verdict; every
    non-pass check detail is collected into ``warnings`` for the app."""
    route = read_default_route()
    iface = route[0] if route else None
    connection = classify_interface(iface, has_wireless_ext(iface)) if iface else "unknown"
    carrier = read_carrier(iface) if iface else None
    static, tunnel, serving, upstream, fail_open = await asyncio.gather(
        _static_ip_check(iface),
        _tunnel_check(),
        _dns_probe_check("127.0.0.1", 53, DNS_PROBE_NAME_SERVING, _SERVING_PASS, _SERVING_FAIL),
        _dns_probe_check(
            "127.0.0.1", 5335, DNS_PROBE_NAME_UPSTREAM, _UPSTREAM_PASS, _UPSTREAM_FAIL
        ),
        _fail_open_check(),
    )
    checks = {
        "ethernet": ethernet_check(connection, carrier),
        "static_ip": static,
        "dns_serving": serving,
        "upstream_dns": upstream,
        "tunnel": tunnel,
    }
    return {
        "overall": compose_verdict(checks, connection),
        "checks": checks,
        "warnings": [c["detail"] for c in checks.values() if c["status"] != "pass"],
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "fail_open": {"router_secondary_possible": fail_open},
    }
