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
    settings.headscale_bin,
    settings.nextdns_bin,
    "apt-get",        # update check: -s upgrade simulation only (ALLOWED_ARGV)
    "apt",            # update check: list --upgradable only (ALLOWED_ARGV)
    "apt-cache",      # update check: policy lookups only (ALLOWED_ARGV)
    "dpkg-query",     # update check: installed versions only (ALLOWED_ARGV)
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

# Binaries where only specific subcommands (argv[1]) may run — headscale has
# mutating verbs (serve, derpmode, ...) the API must never reach. nextdns
# gets the same treatment: `nextdns install` runs an interactive
# configuration wizard that wedges the brick, so it stays forbidden.
ALLOWED_SUBCOMMANDS: dict[str, set[str]] = {
    "headscale": {"version", "users", "preauthkeys", "nodes"},
    "nextdns": {"version", "status", "config", "activate", "deactivate", "restart"},
}

# Binaries restricted to one exact read-only argv shape. A subcommand gate
# isn't enough here: `apt-get -s install x` would pass a gate keyed on
# argv[1] == "-s" while simulating a mutation. "<pkg>" marks the single
# varying argument position.
ALLOWED_ARGV: dict[str, list[list[str]]] = {
    "apt-get": [["-s", "upgrade"]],
    "apt": [["list", "--upgradable"]],
    "apt-cache": [["policy", "<pkg>"]],
    "dpkg-query": [["-W", "-f=${Version}", "<pkg>"]],
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


def _argv_shape_allowed(argv: list[str]) -> bool:
    args = argv[1:]
    for shape in ALLOWED_ARGV[argv[0]]:
        if len(args) != len(shape):
            continue
        if all(expected == actual or expected == "<pkg>" for expected, actual in zip(shape, args)):
            return True
    return False


async def run(argv: list[str], timeout: float = DEFAULT_TIMEOUT) -> CommandResult:
    if not argv:
        raise CommandError("empty command")
    binary = argv[0]
    if binary not in ALLOWED_BINARIES:
        raise CommandError(f"binary not allowlisted: {binary}")
    if binary in ALLOWED_ARGV and not _argv_shape_allowed(argv):
        requested = " ".join(argv[1:]) or "(no arguments)"
        raise CommandError(f"arguments not allowlisted for {binary}: {requested}")
    allowed = ALLOWED_SUBCOMMANDS.get(binary)
    if allowed is not None and (len(argv) < 2 or argv[1] not in allowed):
        requested = argv[1] if len(argv) > 1 else "(no subcommand)"
        raise CommandError(f"subcommand not allowlisted for {binary}: {requested}")
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
