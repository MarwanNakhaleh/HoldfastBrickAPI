"""System management (DietPi and Raspberry Pi OS).

Presented to the app as "Device": temperature, memory, disk, uptime, updates,
router identification, SSH key install, and a (confirmed-in-app) reboot.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re
import secrets
import socket
import struct
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from ..auth import require_token, sliding_window_allowed
from ..config import settings, state
from ..models import ActionResponse, ConfirmCodeResponse, ServiceHealth
from ..runner import CommandError, run, systemd_action, systemd_status

router = APIRouter(prefix="/system", tags=["system"], dependencies=[Depends(require_token)])

ROUTE_FILE = Path("/proc/net/route")
ARP_FILE = Path("/proc/net/arp")
AUTHORIZED_KEYS_FILE = Path("/root/.ssh/authorized_keys")

# Minutes a successful reboot request silences further ones.
REBOOT_COOLDOWN_SECONDS = 600

# The confirmation code shown at the brick before an SSH key may be installed.
CONFIRM_CODE_TTL_SECONDS = 300
# Drop-in that closes password logins once key access exists. Debian ships
# an `Include /etc/ssh/sshd_config.d/*.conf` line in stock sshd_config.
SSHD_HARDENING_FILE = Path("/etc/ssh/sshd_config.d/holdfast-hardening.conf")
SSHD_HARDENING_CONTENT = "PasswordAuthentication no\n"
SSHD_UNIT = "ssh"  # the sshd unit's name on Debian
# Marks authorized_keys lines this API installed; removal drops exactly these.
MANAGED_KEY_TAG = "# holdfastbrick-managed"


def _now() -> float:
    """Wall clock, indirected so tests can move time."""
    return time.time()


# --- default route / gateway (pure parsing, /proc only — no subprocess) ------

def parse_default_route(route_text: str) -> tuple[str, str] | None:
    """Parse /proc/net/route text → (interface, gateway_ip) of the default
    route, or None. Addresses are hex-encoded little-endian IPv4."""
    for line in route_text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 4:
            continue
        iface, destination, gateway, flags = fields[0], fields[1], fields[2], fields[3]
        try:
            if int(destination, 16) != 0 or not int(flags, 16) & 0x2:  # RTF_GATEWAY
                continue
            gateway_ip = socket.inet_ntoa(struct.pack("<I", int(gateway, 16)))
        except (ValueError, struct.error):
            continue
        return iface, gateway_ip
    return None


def read_default_route() -> tuple[str, str] | None:
    try:
        return parse_default_route(ROUTE_FILE.read_text())
    except OSError:
        return None


async def health() -> ServiceHealth:
    # If we can answer at all, the device is up.
    return ServiceHealth(id="system", name="Device", running=True, detail="online")


async def _cpu_temp_celsius() -> float | None:
    # Prefer vcgencmd on Raspberry Pi, fall back to sysfs thermal zone.
    try:
        result = await run(["vcgencmd", "measure_temp"])
        if result.ok:
            match = re.search(r"temp=([\d.]+)", result.stdout)
            if match:
                return float(match.group(1))
    except CommandError:
        pass
    try:
        result = await run(["cat", "/sys/class/thermal/thermal_zone0/temp"])
        if result.ok and result.stdout.strip().isdigit():
            return int(result.stdout.strip()) / 1000.0
    except CommandError:
        pass
    return None


@router.get("/info")
async def get_info() -> dict:
    hostname = await run(["hostname"])
    uptime = await run(["uptime", "-p"])
    mem = await run(["free", "-m"])
    disk = await run(["df", "-h", "/"])

    mem_total = mem_used = None
    for line in mem.stdout.splitlines():
        if line.startswith("Mem:"):
            parts = line.split()
            if len(parts) >= 3:
                mem_total, mem_used = int(parts[1]), int(parts[2])

    disk_percent = None
    lines = disk.stdout.splitlines()
    if len(lines) >= 2:
        parts = lines[1].split()
        if len(parts) >= 5:
            disk_percent = parts[4]

    # Distro name, works on DietPi and Raspberry Pi OS alike.
    os_name = None
    try:
        os_release = await run(["cat", "/etc/os-release"])
        if os_release.ok:
            for line in os_release.stdout.splitlines():
                if line.startswith("PRETTY_NAME="):
                    os_name = line.partition("=")[2].strip().strip('"') or None
                    break
    except CommandError:
        pass

    dietpi_version = None
    try:
        version_file = await run(["cat", "/boot/dietpi/.version"])
        if version_file.ok:
            values = dict(
                line.partition("=")[::2] for line in version_file.stdout.splitlines() if "=" in line
            )
            core = values.get("G_DIETPI_VERSION_CORE", "").strip("'\"")
            sub = values.get("G_DIETPI_VERSION_SUB", "").strip("'\"")
            rc = values.get("G_DIETPI_VERSION_RC", "").strip("'\"")
            if core:
                dietpi_version = ".".join(v for v in (core, sub, rc) if v)
    except CommandError:
        pass

    return {
        "hostname": hostname.stdout.strip(),
        "uptime": uptime.stdout.strip().removeprefix("up ").strip(),
        "cpu_temp_celsius": await _cpu_temp_celsius(),
        "memory_total_mb": mem_total,
        "memory_used_mb": mem_used,
        "disk_used_percent": disk_percent,
        "os": os_name,
        "dietpi_version": dietpi_version,
    }


@router.post("/reboot")
async def reboot() -> ActionResponse:
    """Reboot the Pi. The iOS app shows a confirmation dialog before calling.

    A stolen token must not be able to reboot-loop the household's DNS
    resolver, so requests are cooled down: a second one within 10 minutes
    of a successful reboot request is refused."""
    last = state.get_last_reboot_at()
    now = _now()
    if last is not None and now - last < REBOOT_COOLDOWN_SECONDS:
        minutes_left = max(1, round((REBOOT_COOLDOWN_SECONDS - (now - last)) / 60))
        raise HTTPException(
            status_code=409,
            detail=(
                "The brick was asked to reboot less than 10 minutes ago. "
                f"If it's still misbehaving, try again in about {minutes_left} minutes."
            ),
        )
    try:
        result = await run(["shutdown", "-r", "+0"], timeout=10.0)
    except CommandError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    if result.ok:
        state.set_last_reboot_at(now)
    return ActionResponse(ok=result.ok, message="Rebooting…" if result.ok else result.output)


# --- router identification ---------------------------------------------------

# Best-effort OUI heuristics: first-3-octet MAC prefixes of common consumer
# gateway hardware, used only to tailor in-app help text ("here's how to turn
# off DHCP on an Xfinity gateway"). OUIs are reused/reassigned and vendors ship
# many more prefixes than these — an unknown prefix simply means generic copy,
# never an error. Do not treat this mapping as authoritative.
_ROUTER_OUI_PREFIXES: dict[str, str] = {
    # Xfinity/Comcast gateways (built by Technicolor/Vantiva and ARRIS)
    "44:65:7f": "xfinity",  # Technicolor
    "fc:ae:34": "xfinity",  # Technicolor
    "a8:9f:ec": "xfinity",  # Technicolor
    "cc:a2:70": "xfinity",  # Technicolor/Vantiva
    "00:1d:d0": "xfinity",  # ARRIS
    "90:3e:ab": "xfinity",  # ARRIS
    "fc:51:a4": "xfinity",  # ARRIS
    "14:ab:f0": "xfinity",  # ARRIS
    # NETGEAR
    "9c:3d:cf": "netgear",
    "a0:40:a0": "netgear",
    "20:e5:2a": "netgear",
    # TP-Link
    "50:c7:bf": "tplink",
    "84:d8:1b": "tplink",
    "c0:06:c3": "tplink",
    # eero
    "f8:bb:bf": "eero",
    "60:5f:8d": "eero",
    # ASUS
    "04:d9:f5": "asus",
    "2c:fd:a1": "asus",
    # Verizon (Fios)
    "c8:a7:0a": "verizon",  # Actiontec
    "3c:bd:c5": "verizon",  # Arcadyan
    # AT&T
    "00:1e:46": "att",  # 2Wire
    "84:e0:58": "att",  # Pace
    "88:71:b1": "att",  # Nokia
}

_ROUTER_VENDOR_NAMES: dict[str, str] = {
    "xfinity": "Xfinity / Comcast gateway",
    "netgear": "NETGEAR router",
    "tplink": "TP-Link router",
    "eero": "eero router",
    "asus": "ASUS router",
    "verizon": "Verizon router",
    "att": "AT&T gateway",
}


def lookup_router_vendor(mac: str) -> tuple[str, str]:
    """(vendor_key, friendly name) from a MAC's OUI prefix; unknown → generic."""
    prefix = mac.strip().lower().replace("-", ":")[:8]
    key = _ROUTER_OUI_PREFIXES.get(prefix, "unknown")
    return key, _ROUTER_VENDOR_NAMES.get(key, "Your router")


def parse_arp_mac(arp_text: str, ip: str) -> str:
    """MAC for ``ip`` from /proc/net/arp text, or "" if absent/incomplete."""
    for line in arp_text.splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 4 and fields[0] == ip:
            mac = fields[3].lower()
            if mac != "00:00:00:00:00:00":
                return mac
    return ""


@router.get("/router")
async def get_router() -> dict:
    """Identify the user's router so the app can show tailored 'turn off your
    router's DHCP' instructions. /proc only — no network calls."""
    route = read_default_route()
    gateway_ip = route[1] if route else ""
    gateway_mac = ""
    if gateway_ip:
        try:
            gateway_mac = parse_arp_mac(ARP_FILE.read_text(), gateway_ip)
        except OSError:
            gateway_mac = ""
    vendor_key, vendor = lookup_router_vendor(gateway_mac) if gateway_mac else ("unknown", "Your router")
    return {
        "gateway_ip": gateway_ip,
        "gateway_mac": gateway_mac,
        "vendor": vendor,
        "vendor_key": vendor_key,
        "portal_url": f"http://{gateway_ip}" if gateway_ip else "",
    }


# --- self-update -------------------------------------------------------------

@router.post("/update")
async def start_update() -> ActionResponse:
    """Pull the latest code and re-run the installer.

    Launched DETACHED via systemd-run: install.sh restarts holdfastbrick-api,
    which would kill an updater running inside this process halfway through.
    A transient systemd unit survives the restart and --collect cleans it up.
    """
    if not settings.repo_dir:
        raise HTTPException(
            status_code=422,
            detail=(
                "HOLDFASTBRICK_REPO_DIR isn't configured. Re-run deploy/install.sh "
                "on the device once to record where the repo lives."
            ),
        )
    try:
        result = await run(
            [
                "systemd-run",
                "--unit=holdfastbrick-update",
                "--collect",
                "/bin/bash",
                f"{settings.repo_dir}/deploy/self-update.sh",
                settings.repo_dir,
            ]
        )
    except CommandError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    if not result.ok:
        raise HTTPException(status_code=503, detail=result.output or "systemd-run failed")
    return ActionResponse(
        ok=True,
        message="Update started — the brick will restart its API; check the version in a minute.",
    )


@router.get("/update/status")
async def update_status() -> dict:
    """Whether the transient holdfastbrick-update unit is still running.

    An unknown/inactive unit means "not running", not an error — after
    --collect the unit vanishes entirely once it finishes.
    """
    try:
        status = await systemd_status("holdfastbrick-update")
        return {"running": bool(status["running"])}
    except CommandError:
        return {"running": False}


# --- SSH public key install --------------------------------------------------

# This string lands in /root/.ssh/authorized_keys — treat it as hostile input.
# Exactly "ssh-ed25519 <base64> [comment]": no options prefix (command=...,
# environment=...), no newlines (a second line would be a second key), single
# spaces only, conservative comment charset. \Z (not $) so a trailing newline
# can't sneak past the anchor.
_SSH_ED25519_RE = re.compile(
    r"^ssh-ed25519 (?P<b64>[A-Za-z0-9+/]+={0,2})(?: (?P<comment>[A-Za-z0-9@._-]{1,128}))?\Z"
)
# ed25519 wire format: uint32 len + "ssh-ed25519" + uint32 len + 32-byte key.
_SSH_ED25519_BLOB_PREFIX = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 "
_SSH_ED25519_BLOB_LENGTH = 51
_SSH_KEY_MAX_LENGTH = 1000


def validate_ssh_ed25519_key(raw: str) -> str:
    """Validate an OpenSSH ed25519 public key; return it normalized (outer
    whitespace stripped) or raise ValueError."""
    if len(raw) >= _SSH_KEY_MAX_LENGTH:
        raise ValueError("public key is too long")
    key = raw.strip()
    if "\n" in key or "\r" in key or "\x00" in key:
        raise ValueError("public key must be a single line")
    match = _SSH_ED25519_RE.match(key)
    if match is None:
        raise ValueError("expected 'ssh-ed25519 <base64> [comment]'")
    try:
        blob = base64.b64decode(match.group("b64"), validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("key data is not valid base64")
    if len(blob) != _SSH_ED25519_BLOB_LENGTH or not blob.startswith(_SSH_ED25519_BLOB_PREFIX):
        raise ValueError("key data is not an ed25519 public key")
    return key


class SshKeyRequest(BaseModel):
    public_key: str
    confirm_code: str = ""


# --- physical-presence confirmation -------------------------------------------

@router.post("/confirm-code", response_model=ConfirmCodeResponse)
async def create_confirm_code() -> ConfirmCodeResponse:
    """Mint the 6-digit confirmation code that POST /system/ssh-key demands.

    The code is printed on the brick's console (and lands in its service
    journal) only — this response never carries it. That is the point: the
    bearer token alone must not be enough to install a root SSH key, so
    being physically at the brick is the second gate. Read the code off the
    brick and post it with your public key within 5 minutes. Single use."""
    code = f"{secrets.randbelow(1_000_000):06d}"
    expires_at = _now() + CONFIRM_CODE_TTL_SECONDS
    state.set_confirm_code(code, expires_at)
    print()
    print("  ┌────────────────────────────────────────┐")
    print("  │         Holdfast confirmation          │")
    print("  │                                        │")
    print(f"  │        Code:  {code[:3]} {code[3:]}                  │")
    print("  │                                        │")
    print("  │   Enter this in the app to install     │")
    print("  │   an SSH key. 5 minutes. Single use.   │")
    print("  └────────────────────────────────────────┘")
    print()
    return ConfirmCodeResponse(
        expires_at=datetime.fromtimestamp(expires_at, tz=timezone.utc).isoformat()
    )


def _consume_confirm_code(code: str) -> bool:
    """True when ``code`` matches the minted, unexpired confirmation code.
    Single use: a matching code is consumed immediately, so replaying it —
    even seconds later — fails."""
    stored = state.get_confirm_code()
    if not stored:
        return False
    if _now() > float(stored.get("expires_at", 0)):
        state.clear_confirm_code()
        return False
    if not secrets.compare_digest(str(stored.get("code", "")), code):
        return False
    state.clear_confirm_code()
    return True


# --- sshd password-auth hardening ----------------------------------------------

def sshd_hardening_applied() -> bool:
    """Whether the drop-in is on disk exactly as this API writes it."""
    try:
        return (
            SSHD_HARDENING_FILE.exists()
            and SSHD_HARDENING_FILE.read_text() == SSHD_HARDENING_CONTENT
        )
    except OSError:
        return False


def write_sshd_hardening() -> bool:
    """Write the drop-in that turns off SSH password authentication.

    Idempotent: returns True only when the file was actually (re)written so
    the caller can reload sshd just on real changes. False — including on a
    write failure — never blocks the key install itself; the drop-in will
    apply on sshd's next restart instead."""
    try:
        if sshd_hardening_applied():
            return False
        SSHD_HARDENING_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = SSHD_HARDENING_FILE.with_name(SSHD_HARDENING_FILE.name + ".tmp")
        tmp.write_text(SSHD_HARDENING_CONTENT)
        tmp.replace(SSHD_HARDENING_FILE)
        return True
    except OSError:
        return False


def build_authorized_line(key: str, client_ip: str) -> str:
    """The authorized_keys entry for ``key``: source-restricted to the
    installing device's IP when we know it. The IP is validated (it must
    parse as an address) before being placed inside the from= option, so
    nothing attacker-shaped can extend the option list. Every line we
    install carries a trailing tag so DELETE /system/ssh-key can remove
    exactly our lines and nothing else."""
    line = key
    if client_ip:
        try:
            ipaddress.ip_address(client_ip)
        except ValueError:
            pass
        else:
            line = f'from="{client_ip}" {key}'
    return f"{line} {MANAGED_KEY_TAG}"


def remove_authorized_lines(existing: str, tag: str = MANAGED_KEY_TAG) -> tuple[str, int]:
    """authorized_keys text without any line carrying ``tag``.

    Returns (remaining_text, lines_removed). Lines installed any other way —
    by hand, or by app versions before tagging existed — are preserved."""
    entries = existing.splitlines()
    kept = [entry for entry in entries if tag not in entry]
    return ("\n".join(kept) + "\n" if kept else ""), len(entries) - len(kept)


def merge_authorized_keys(existing: str, blob: str, line: str) -> tuple[str | None, str]:
    """Merge ``line`` (whose key blob is ``blob``) into authorized_keys text.

    Returns (new_content_or_None, message): None content means nothing to
    write (the key is present with the same source restriction — comment
    differences don't count). If the key exists with a different from=
    restriction, its line is replaced so the whitelist follows the
    device's current address."""

    def options_prefix(entry: str) -> str:
        idx = entry.find("ssh-ed25519")
        return entry[:idx].strip() if idx > 0 else ""

    lines = existing.splitlines()
    out: list[str] = []
    replaced = False
    for entry in lines:
        if blob in entry:
            if options_prefix(entry.strip()) == options_prefix(line):
                return None, "Key already installed"
            out.append(line)
            replaced = True
        else:
            out.append(entry)
    if replaced:
        return "\n".join(out) + "\n", "SSH access updated for this device's address"
    out.append(line)
    return "\n".join(out) + "\n", "Key installed"


@router.post("/ssh-key")
async def install_ssh_key(body: SshKeyRequest, request: Request) -> ActionResponse:
    """Install an ed25519 public key for root SSH access (power-user escape
    hatch). Two gates: the standing bearer token, and fresh proof someone is
    at the brick — a 6-digit confirmation code minted by
    POST /system/confirm-code and shown only on the brick's console.

    The key is source-restricted via from= to the caller's IP — re-posting
    from a new address moves the restriction along. The first install also
    writes the sshd drop-in that turns password authentication off and
    reloads ssh;     later installs keep that drop-in in place, never duplicated."""
    # The confirmation code is a 6-digit secret with a 5-minute life, so the
    # install endpoint gets the same per-address sliding window as pairing;
    # without it, a stolen token could grind through the code's keyspace.
    source_ip = request.client.host if request.client else ""
    if not sliding_window_allowed(f"ssh-key:{source_ip}"):
        raise HTTPException(
            status_code=429,
            detail=(
                "Too many confirmation attempts from your address. Wait a "
                "minute and try again."
            ),
        )
    try:
        key = validate_ssh_ed25519_key(body.public_key)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Not a valid ed25519 public key: {exc}")
    # Dedupe on type + base64 blob, ignoring the comment.
    blob = " ".join(key.split(" ")[:2])
    existing = ""
    try:
        existing = AUTHORIZED_KEYS_FILE.read_text() if AUTHORIZED_KEYS_FILE.exists() else ""
    except OSError as exc:
        raise HTTPException(status_code=503, detail=f"Couldn't read authorized_keys: {exc}")
    # Fresh proof of physical presence gates NEW credentials only: re-posting
    # a key that is already installed just moves its from= restriction to the
    # caller's current address (the connect flow does this on every IP
    # change), and demanding a console code there would make the console
    # unusable away from the brick.
    if blob not in existing and not _consume_confirm_code(body.confirm_code):
        raise HTTPException(
            status_code=403,
            detail=(
                "Missing or wrong confirmation code. Read the code shown on "
                "the brick (mint a fresh one in the app) and try again "
                "within 5 minutes."
            ),
        )
    client_ip = request.client.host if request.client else ""
    line = build_authorized_line(key, client_ip)
    try:
        ssh_dir = AUTHORIZED_KEYS_FILE.parent
        ssh_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        ssh_dir.chmod(0o700)
        content, message = merge_authorized_keys(existing, blob, line)
        if content is not None:
            # tmp + rename: an interrupted write must never truncate
            # previously authorized keys (root lockout on SD-card power loss).
            tmp = AUTHORIZED_KEYS_FILE.with_name("authorized_keys.holdfastbrick-tmp")
            tmp.write_text(content)
            tmp.chmod(0o600)
            tmp.replace(AUTHORIZED_KEYS_FILE)
        AUTHORIZED_KEYS_FILE.chmod(0o600)
    except OSError as exc:
        raise HTTPException(status_code=503, detail=f"Couldn't write authorized_keys: {exc}")
    if write_sshd_hardening():
        try:
            await systemd_action(SSHD_UNIT, "reload")
        except CommandError:
            message += (
                " (couldn't reload the SSH service; the change applies on "
                "its next restart)"
            )
    return ActionResponse(ok=True, message=message)


@router.delete("/ssh-key")
async def delete_ssh_key() -> ActionResponse:
    """Remove every authorized_keys line this API installed (exactly the
    lines tagged '# holdfastbrick-managed') and report how many. Keys
    installed by hand — including by app versions before tagging existed —
    are left alone."""
    try:
        existing = (
            AUTHORIZED_KEYS_FILE.read_text() if AUTHORIZED_KEYS_FILE.exists() else ""
        )
    except OSError as exc:
        raise HTTPException(status_code=503, detail=f"Couldn't read authorized_keys: {exc}")
    remaining, removed = remove_authorized_lines(existing)
    if removed:
        try:
            tmp = AUTHORIZED_KEYS_FILE.with_name("authorized_keys.holdfastbrick-tmp")
            tmp.write_text(remaining)
            tmp.chmod(0o600)
            tmp.replace(AUTHORIZED_KEYS_FILE)
        except OSError as exc:
            raise HTTPException(status_code=503, detail=f"Couldn't write authorized_keys: {exc}")
    return ActionResponse(
        ok=True,
        message=f"Removed {removed} holdfastbrick-managed SSH key line(s).",
    )
