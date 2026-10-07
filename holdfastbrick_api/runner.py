"""Safe subprocess execution for wrapping CLIs.

Rules:
- Never uses a shell; commands are argv lists.
- Every command must start with an allowlisted binary.
- Hard timeout on everything so a hung CLI can't wedge the API.
"""

from __future__ import annotations

import asyncio
import shutil
from dataclasses import dataclass

from .config import settings

# Binaries this API is ever allowed to execute. Anything else is refused.
ALLOWED_BINARIES = {
    settings.unbound_control_bin,
    settings.tailscale_bin,
    settings.nextdns_bin,
    "systemctl",
    "hostname",
    "uptime",
    "vcgencmd",       # Pi temperature / throttling
    "free",
    "df",
    "cat",
    "dietpi-update",
    "shutdown",
    "systemd-run",    # detached self-update (deploy/self-update.sh)
    "nmcli",          # static-IP pinning on NetworkManager systems (Raspberry Pi OS)
}

DEFAULT_TIMEOUT = 20.0


@dataclass
class CommandResult:
    ok: bool
    exit_code: int
    stdout: str
    stderr: str

    @property
    def output(self) -> str:
        return self.stdout if self.stdout else self.stderr


class CommandError(Exception):
    def __init__(self, message: str, result: CommandResult | None = None):
        super().__init__(message)
        self.result = result


async def run(argv: list[str], timeout: float = DEFAULT_TIMEOUT) -> CommandResult:
    if not argv:
        raise CommandError("empty command")
    binary = argv[0]
    if binary not in ALLOWED_BINARIES:
        raise CommandError(f"binary not allowlisted: {binary}")
    resolved = shutil.which(binary)
    if resolved is None:
        raise CommandError(f"binary not installed: {binary}")

    proc = await asyncio.create_subprocess_exec(
        resolved,
        *argv[1:],
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        raise CommandError(f"command timed out after {timeout}s: {' '.join(argv)}")

    return CommandResult(
        ok=proc.returncode == 0,
        exit_code=proc.returncode or 0,
        stdout=stdout.decode(errors="replace").strip(),
        stderr=stderr.decode(errors="replace").strip(),
    )


async def systemd_status(unit: str) -> dict:
    """Return a friendly summary of a systemd unit's state."""
    result = await run(["systemctl", "is-active", unit])
    active = result.stdout.strip() == "active"
    enabled_result = await run(["systemctl", "is-enabled", unit])
    return {
        "unit": unit,
        "running": active,
        "state": result.stdout.strip() or "unknown",
        "enabled": enabled_result.stdout.strip() in ("enabled", "static"),
    }


async def systemd_action(unit: str, action: str) -> CommandResult:
    if action not in ("start", "stop", "restart"):
        raise CommandError(f"unsupported systemd action: {action}")
    return await run(["systemctl", action, unit], timeout=60.0)
