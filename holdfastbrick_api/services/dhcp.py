"""AdGuard Home DHCP takeover — proxied via its local REST API.

Lets the app move DHCP duty from the user's router onto the Holdfast Brick, so
every device on the LAN automatically gets the Pi as its DNS server. The flow
is: check (is the router's DHCP still on? is the Pi's own IP static?), then
enable (pin the Pi's IP if needed, pick a lease range, turn AdGuard DHCP on),
with disable as the undo.

Pure logic (range picking, route parsing) lives in plain functions so it is
unit-testable without root or AdGuard; IP-configuration primitives live in
ipconfig.py.
"""

from __future__ import annotations

import ipaddress

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ..auth import require_token
from ..models import ActionResponse
from .adguard import _client, _proxy_error
from .ipconfig import (
    INTERFACES_BACKUP,
    INTERFACES_FILE,
    _STATIC_IP_HINT,
    _interface_netmask,
    _pin_static_via_networkmanager,
    _write_atomic,
    interfaces_static_state,
    is_wifi,
    pick_lan_interface,
    rewrite_interfaces_static,
)
from .system import read_default_route

router = APIRouter(prefix="/dhcp", tags=["dhcp"], dependencies=[Depends(require_token)])

LEASE_DURATION_SECONDS = 86400


# --- pure logic (unit-testable) ---------------------------------------------

def pick_dhcp_range(
    pi_ip: str, gateway_ip: str, netmask: str = "255.255.255.0"
) -> tuple[str, str]:
    """Pick a DHCP range inside the actual subnet of ``pi_ip``/``netmask``.

    Candidate spans are tried in order; the first one containing neither the
    Pi's IP nor the gateway wins. For /24-or-larger networks the familiar
    (.100-.199), (.200-.249), (.10-.99) offsets are used; smaller subnets are
    split into two halves of their usable host space.
    """
    network = ipaddress.ip_network(f"{pi_ip}/{netmask}", strict=False)
    occupied: set[int] = set()
    for ip_str in (pi_ip, gateway_ip):
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if addr in network:
            occupied.add(int(addr))
    net_int = int(network.network_address)
    if network.num_addresses >= 256:
        candidates = ((100, 199), (200, 249), (10, 99))
    else:
        # Small subnet: skip network addr + a few low addresses (router
        # convention) and the broadcast addr, then offer each half.
        first, last = 5, network.num_addresses - 2
        if last - first < 8:
            raise ValueError(f"subnet {network} is too small for a DHCP range")
        mid = (first + last) // 2
        candidates = ((first, mid), (mid + 1, last))
    for lo, hi in candidates:
        lo_int, hi_int = net_int + lo, net_int + hi
        if not any(lo_int <= occ <= hi_int for occ in occupied):
            return str(ipaddress.ip_address(lo_int)), str(ipaddress.ip_address(hi_int))
    raise ValueError(f"no free DHCP range in {network} avoiding the Pi and gateway")


async def _run_check() -> dict:
    """Shared logic for /check and the guards in /enable."""
    default = read_default_route()
    try:
        async with _client() as client:
            resp = await client.get("/control/dhcp/interfaces")
            resp.raise_for_status()
            interfaces = resp.json() or {}
            iface = pick_lan_interface(interfaces, default[0] if default else None)
            if iface is None:
                raise HTTPException(
                    status_code=422,
                    detail="No LAN interface with an IPv4 gateway found — is the Pi on the network?",
                )
            name = iface.get("name", "")
            resp = await client.post("/control/dhcp/find_active_dhcp", json={"interface": name})
            resp.raise_for_status()
            found = resp.json() or {}
    except httpx.HTTPError as exc:
        raise _proxy_error(exc) from exc
    v4 = found.get("v4") or {}
    other = v4.get("other_server") or {}
    static = v4.get("static_ip") or {}
    ipv4s = iface.get("ipv4_addresses") or []
    return {
        "interface": name,
        "pi_ip": ipv4s[0] if ipv4s else "",
        "gateway_ip": iface.get("gateway_ip", ""),
        "other_dhcp": other.get("found", "error"),
        "other_dhcp_error": other.get("error", "") or "",
        "static_ip": static.get("static", "error"),
    }


# --- endpoints ----------------------------------------------------------------

@router.get("/status")
async def get_status() -> dict:
    """Normalized view of AdGuard's DHCP server state."""
    try:
        async with _client() as client:
            resp = await client.get("/control/dhcp/status")
            resp.raise_for_status()
            data = resp.json() or {}
    except httpx.HTTPError as exc:
        raise _proxy_error(exc) from exc
    v4 = data.get("v4") or {}
    return {
        "enabled": bool(data.get("enabled", False)),
        "interface": data.get("interface_name", "") or "",
        "gateway": v4.get("gateway_ip", "") or "",
        "range_start": v4.get("range_start", "") or "",
        "range_end": v4.get("range_end", "") or "",
        "lease_count": len(data.get("leases") or []),
    }


@router.post("/check")
async def check() -> dict:
    """Pre-flight for DHCP takeover: is the router's DHCP still answering,
    and is the Pi's own IP static?"""
    return await _run_check()


class EnableRequest(BaseModel):
    force: bool = False


@router.post("/enable")
async def enable(body: EnableRequest | None = None) -> dict:
    force = body.force if body is not None else False

    # Guard 0: WiFi takeover is blocked outright (founder rule) — a brick
    # handing out addresses over its radio drops the whole household when
    # the radio hiccups. Not overridable with force.
    route = read_default_route()
    if route and is_wifi(route[0]):
        raise HTTPException(
            status_code=409,
            detail=(
                "Holdfast Brick needs a wired connection to hand out addresses. "
                "Move it to ethernet, then try again."
            ),
        )

    # Guard 1: don't create a second DHCP server on the LAN.
    result = await _run_check()
    if result["other_dhcp"] == "yes" and not force:
        raise HTTPException(
            status_code=409,
            detail="Your router's DHCP server is still on — turn it off first, then try again.",
        )

    iface = result["interface"]
    pi_ip = result["pi_ip"]
    gateway = result["gateway_ip"]
    if not pi_ip or not gateway:
        raise HTTPException(
            status_code=422,
            detail="Couldn't determine the Pi's IP and gateway on the LAN interface.",
        )
    netmask = _interface_netmask(iface)

    # Compute the range BEFORE any mutation, so a range failure can't leave
    # a half-finished takeover behind.
    try:
        range_start, range_end = pick_dhcp_range(pi_ip, gateway, netmask)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    # Guard 2: a DHCP server must not itself have a DHCP-assigned address —
    # pin the Pi's current IP as static before taking over. Fail closed:
    # anything but a confirmed "yes" from AdGuard's probe takes this path
    # (its probe can misread ifupdown systems, so the file is the authority).
    needs_reboot = False
    if result["static_ip"] != "yes":
        try:
            content = INTERFACES_FILE.read_text()
        except OSError:
            raise HTTPException(status_code=422, detail=_STATIC_IP_HINT)
        state = interfaces_static_state(content, iface)
        if state == "dhcp":
            rewritten = rewrite_interfaces_static(content, iface, pi_ip, netmask, gateway)
            _write_atomic(INTERFACES_BACKUP, content)
            _write_atomic(INTERFACES_FILE, rewritten)
            needs_reboot = True
        elif state == "pinned":
            # A previous enable already rewrote the file (and then failed
            # later, or the user hasn't rebooted yet) — nothing to redo.
            needs_reboot = True
        elif state == "static":
            pass  # user-configured static IP; trust it
        elif await _pin_static_via_networkmanager(iface, pi_ip, netmask, gateway):
            # Raspberry Pi OS: no ifupdown stanza, NetworkManager owns the
            # interface — pinned via nmcli, applies at reboot.
            needs_reboot = True
        else:
            raise HTTPException(status_code=422, detail=_STATIC_IP_HINT)

    config = {
        "enabled": True,
        "interface_name": iface,
        "v4": {
            "gateway_ip": gateway,
            "subnet_mask": netmask,
            "range_start": range_start,
            "range_end": range_end,
            "lease_duration": LEASE_DURATION_SECONDS,
        },
    }
    try:
        async with _client() as client:
            resp = await client.post("/control/dhcp/set_config", json=config)
            resp.raise_for_status()
    except httpx.HTTPError as exc:
        if needs_reboot:
            # The interfaces file was already rewritten — say so, or a retry
            # error would wrongly suggest the static IP still needs setup.
            base = _proxy_error(exc)
            raise HTTPException(
                status_code=base.status_code,
                detail=(
                    "The Pi's IP was pinned static (backup at "
                    f"{INTERFACES_BACKUP}), but enabling AdGuard's DHCP "
                    f"failed: {base.detail} Fix that, then try again — the "
                    "static IP step won't repeat."
                ),
            ) from exc
        raise _proxy_error(exc) from exc

    message = f"Holdfast Brick is now handing out addresses {range_start}–{range_end}."
    if needs_reboot:
        message += " The Pi's IP was pinned static — reboot it to finish."
    return {"ok": True, "message": message, "needs_reboot": needs_reboot}


@router.post("/disable")
async def disable() -> ActionResponse:
    """Turn AdGuard's DHCP server back off, keeping the saved config."""
    try:
        async with _client() as client:
            resp = await client.get("/control/dhcp/status")
            resp.raise_for_status()
            data = resp.json() or {}
            # Never configured → nothing to turn off; still report success.
            if data.get("interface_name"):
                v4 = data.get("v4") or {}
                resp = await client.post(
                    "/control/dhcp/set_config",
                    json={
                        "enabled": False,
                        "interface_name": data["interface_name"],
                        "v4": {
                            "gateway_ip": v4.get("gateway_ip", ""),
                            "subnet_mask": v4.get("subnet_mask", ""),
                            "range_start": v4.get("range_start", ""),
                            "range_end": v4.get("range_end", ""),
                            "lease_duration": v4.get("lease_duration", LEASE_DURATION_SECONDS),
                        },
                    },
                )
                resp.raise_for_status()
    except httpx.HTTPError as exc:
        raise _proxy_error(exc) from exc
    return ActionResponse(
        ok=True,
        message="Holdfast Brick's DHCP server is off. Turn your router's DHCP back on.",
    )
