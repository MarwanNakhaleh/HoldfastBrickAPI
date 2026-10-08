"""IP-configuration primitives shared by the DHCP-takeover and Network
services: static-stanza detection and rewriting (ifupdown), NetworkManager
pinning, interface classification. A leaf module — imports nothing from
sibling services — so neither router depends on the other."""

from __future__ import annotations

import fcntl
import ipaddress
import re
import socket
import struct
from pathlib import Path

from fastapi import HTTPException

from ..runner import CommandError, run

INTERFACES_FILE = Path("/etc/network/interfaces")
INTERFACES_BACKUP = Path("/etc/network/interfaces.holdfastbrick-bak")
SIOCGIFNETMASK = 0x891B  # Linux ioctl: get interface netmask

_STATIC_IP_HINT = (
    "Couldn't safely pin a static IP: /etc/network/interfaces has no "
    "recognizable stanza for the interface and NetworkManager isn't managing "
    "it either. Set a static IP on the brick first (dietpi-config on DietPi, "
    "nmtui on Raspberry Pi OS), then try again."
)

PIN_MARKER = "# pinned by Holdfast (dhcp/enable)"

SYS_CLASS_NET = Path("/sys/class/net")
_ETHERNET_PREFIXES = ("eth", "en", "end", "eno", "ens", "usp")


# --- interface classification -------------------------------------------------

def classify_interface(name: str, has_wireless_ext: bool) -> str:
    """Classify an interface name: "wifi", "ethernet", or "unknown".

    Name prefixes decide; the kernel's /sys/class/net/<iface>/wireless
    marker confirms wireless for names nothing known matches.
    """
    if name.startswith("wl"):
        return "wifi"
    if name.startswith(_ETHERNET_PREFIXES):
        return "ethernet"
    if has_wireless_ext:
        return "wifi"
    return "unknown"


def has_wireless_ext(iface: str) -> bool:
    return (SYS_CLASS_NET / iface / "wireless").exists()


def is_wifi(iface_name: str) -> bool:
    return classify_interface(iface_name, has_wireless_ext(iface_name)) == "wifi"


# --- ifupdown stanzas (/etc/network/interfaces — DietPi) ----------------------

def interfaces_static_state(content: str, iface: str) -> str:
    """Classify the ``iface`` stanza in an interfaces file.

    Returns "dhcp" (rewritable), "pinned" (this code already rewrote it —
    e.g. a previous enable pinned the IP but the AdGuard call after it
    failed), "static" (the user configured static themselves), or
    "unrecognized" (no stanza for the interface at all).
    """
    if re.search(rf"^\s*iface\s+{re.escape(iface)}\s+inet\s+dhcp\s*$", content, re.M):
        return "dhcp"
    if re.search(rf"^\s*iface\s+{re.escape(iface)}\s+inet\s+static\s*$", content, re.M):
        return "pinned" if PIN_MARKER in content else "static"
    return "unrecognized"


def rewrite_interfaces_static(
    content: str, iface: str, address: str, netmask: str, gateway: str
) -> str:
    """Rewrite an ``iface <iface> inet dhcp`` stanza to a static one.

    Only touches the single matching ``iface`` line — every other line
    (loopback stanza, comments, other interfaces) is preserved verbatim.
    Raises ValueError when the file doesn't contain the recognizable
    pattern, so the caller can bail out instead of guessing.
    """
    pattern = re.compile(rf"^(\s*)iface\s+{re.escape(iface)}\s+inet\s+dhcp\s*$")
    out: list[str] = []
    replaced = False
    for line in content.splitlines():
        match = pattern.match(line)
        if match and not replaced:
            indent = match.group(1)
            out.append(f"{indent}{PIN_MARKER}")
            out.append(f"{indent}iface {iface} inet static")
            out.append(f"{indent}    address {address}")
            out.append(f"{indent}    netmask {netmask}")
            out.append(f"{indent}    gateway {gateway}")
            out.append(f"{indent}    dns-nameservers 127.0.0.1")
            replaced = True
        else:
            out.append(line)
    if not replaced:
        raise ValueError(f"no 'iface {iface} inet dhcp' stanza found")
    return "\n".join(out) + "\n"


def _write_atomic(path: Path, content: str) -> None:
    """tmp + rename, same pattern as StateStore._save — an interrupted write
    must never leave a truncated network config on this SD-card device."""
    tmp = path.with_name(path.name + ".holdfastbrick-tmp")
    tmp.write_text(content)
    tmp.replace(path)


def netmask_to_prefix(netmask: str) -> int:
    return ipaddress.IPv4Network(f"0.0.0.0/{netmask}").prefixlen


# --- NetworkManager (Raspberry Pi OS) ----------------------------------------

async def _nm_connection_for(iface: str) -> str | None:
    """Name of the active NetworkManager connection on ``iface``, or None
    when NetworkManager isn't present/running or doesn't manage it."""
    try:
        result = await run(["nmcli", "-t", "-f", "NAME,DEVICE", "connection", "show", "--active"])
    except CommandError:
        return None
    if not result.ok:
        return None
    for line in result.stdout.splitlines():
        # Terse mode separates with ':'; literal colons in names arrive as '\:'.
        parts = re.split(r"(?<!\\):", line.strip())
        if len(parts) >= 2 and parts[1] == iface:
            return parts[0].replace("\\:", ":")
    return None


async def _pin_static_via_networkmanager(
    iface: str, pi_ip: str, netmask: str, gateway: str
) -> bool:
    """Pin the current address via nmcli (applies at reboot/reconnect).
    Returns False when NetworkManager isn't managing the interface, so the
    caller can fall through to its manual-setup hint. Idempotent."""
    conn = await _nm_connection_for(iface)
    if conn is None:
        return False
    result = await run([
        "nmcli", "connection", "modify", conn,
        "ipv4.method", "manual",
        "ipv4.addresses", f"{pi_ip}/{netmask_to_prefix(netmask)}",
        "ipv4.gateway", gateway,
        "ipv4.dns", "127.0.0.1",
    ])
    if not result.ok:
        raise HTTPException(
            status_code=502,
            detail=f"NetworkManager refused the static IP: {result.output}",
        )
    return True


def pick_lan_interface(interfaces: dict, default_iface: str | None) -> dict | None:
    """Pick the LAN interface from AdGuard's /control/dhcp/interfaces map.

    Prefer the interface carrying the default route; otherwise the first one
    that has an IPv4 gateway at all.
    """
    candidates = {
        name: info
        for name, info in interfaces.items()
        if isinstance(info, dict) and info.get("gateway_ip")
    }
    if default_iface and default_iface in candidates:
        return candidates[default_iface]
    return next(iter(candidates.values()), None)


# --- host helpers ------------------------------------------------------------

def _interface_netmask(iface: str) -> str:
    """Netmask of ``iface`` via the SIOCGIFNETMASK ioctl; /24 as a fallback."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            packed = fcntl.ioctl(
                sock.fileno(),
                SIOCGIFNETMASK,
                struct.pack("256s", iface.encode()[:15]),
            )
        return socket.inet_ntoa(packed[20:24])
    except OSError:
        return "255.255.255.0"
