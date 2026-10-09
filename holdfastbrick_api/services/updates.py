"""Software update check — OS packages and stack component freshness.

Answers "is anything on the brick outdated?" without changing anything: apt
simulations for the OS layer, vendor CLIs and release APIs for the
components. Every probe degrades to nulls, never a 500, so one unreachable
source can't hide the rest of the picture.
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone
from typing import Awaitable, Callable

import httpx
from fastapi import APIRouter, Depends

from ..auth import require_token
from ..config import settings
from ..runner import CommandError, run
from . import adguard

router = APIRouter(prefix="/updates", tags=["updates"], dependencies=[Depends(require_token)])

GITHUB_TIMEOUT = 5.0
# Soft bound on the whole sweep and on each probe within it: whatever hasn't
# finished by then comes back as nulls.
SWEEP_TIMEOUT = 30.0
USER_AGENT = "holdfastbrick-update-check"


# --- version comparison (pure) -------------------------------------------------

def normalize_version(raw: str) -> tuple[int, ...] | None:
    """Comparable form of a version string: strip a leading 'v', drop a
    Debian revision or pre-release suffix after '-', keep dotted numerics
    only. None = a shape we can't confidently order."""
    v = raw.strip().lower()
    if v.startswith("v"):
        v = v[1:]
    v = v.split("-", 1)[0]
    parts = v.split(".")
    if not v or not all(part.isdigit() for part in parts):
        return None
    return tuple(int(part) for part in parts)


def compare_versions(current: str, latest: str) -> bool | None:
    """True when latest sorts above current, False when it doesn't, None when
    either side isn't a confidently comparable shape."""
    a, b = normalize_version(current), normalize_version(latest)
    if a is None or b is None:
        return None
    width = max(len(a), len(b))
    a = a + (0,) * (width - len(a))
    b = b + (0,) * (width - len(b))
    return b > a


# --- apt output parsing (pure) -------------------------------------------------

_SUMMARY_RE = re.compile(r"(\d+) upgraded, (\d+) newly installed")
_UPGRADABLE_RE = re.compile(r"^(?P<name>[^\s/]+)/(?P<suites>\S+)\s+(?P<candidate>\S+)")
_UPGRADABLE_FROM_RE = re.compile(r"\[upgradable from: ([^\]]+)\]")


def parse_upgrade_summary(output: str) -> int | None:
    """Upgraded-package count from `apt-get -s upgrade`'s summary line."""
    for line in output.splitlines():
        match = _SUMMARY_RE.search(line)
        if match:
            return int(match.group(1))
    return None


def parse_upgradable_list(output: str) -> list[dict]:
    """[{name, current, candidate, security}] from `apt list --upgradable`.

    Security tagging comes from the suite column: a suite containing
    "-security" (e.g. bookworm-security) marks a security update. current is
    None when the bracket shape isn't the unambiguous one."""
    packages: list[dict] = []
    for line in output.splitlines():
        if not line.strip() or line.startswith("Listing"):
            continue
        match = _UPGRADABLE_RE.match(line)
        if match is None:
            continue
        current = _UPGRADABLE_FROM_RE.search(line)
        packages.append(
            {
                "name": match.group("name"),
                "current": current.group(1) if current else None,
                "candidate": match.group("candidate"),
                "security": any(
                    "-security" in suite for suite in match.group("suites").split(",")
                ),
            }
        )
    return packages


def parse_apt_candidate(output: str) -> str | None:
    """Candidate version from `apt-cache policy` output, None when absent."""
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("Candidate:"):
            value = stripped.partition("Candidate:")[2].strip()
            return value if value and value != "(none)" else None
    return None


# --- current versions ----------------------------------------------------------

def _first_token(line: str) -> str:
    return line.split()[0] if line.split() else ""


def _clean_headscale(line: str) -> str:
    # `headscale version` prints "headscale version 0.23.0 (date)" — the
    # prefix is part of the first line, and the date must not survive.
    return _first_token(line.strip().removeprefix("headscale version ").strip())


async def _cli_current(argv: list[str], clean: Callable[[str], str] = _first_token) -> str | None:
    try:
        result = await run(argv)
    except CommandError:
        return None
    if not result.ok or not result.output:
        return None
    return clean(result.output.splitlines()[0]) or None


async def _dpkg_current(pkg: str) -> str | None:
    try:
        result = await run(["dpkg-query", "-W", "-f=${Version}", pkg])
    except CommandError:
        return None
    return result.output if result.ok else None


# --- latest versions -----------------------------------------------------------

def _github_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=GITHUB_TIMEOUT, headers={"User-Agent": USER_AGENT})


async def _github_latest_tag(repo: str) -> str | None:
    """Latest release tag from the GitHub API, None on any failure. Only the
    tag_name field is read; nothing else in the response is kept."""
    try:
        async with _github_client() as client:
            resp = await client.get(f"https://api.github.com/repos/{repo}/releases/latest")
            resp.raise_for_status()
            tag = resp.json().get("tag_name")
            return str(tag) if tag else None
    except (httpx.HTTPError, ValueError):
        return None


async def _apt_candidate_latest(pkg: str) -> str | None:
    try:
        result = await run(["apt-cache", "policy", pkg])
    except CommandError:
        return None
    return parse_apt_candidate(result.output) if result.ok else None


# --- components ----------------------------------------------------------------

def _component_row(name: str, current: str | None, latest: str | None) -> dict:
    return {
        "name": name,
        "current": current,
        "latest": latest,
        "update_available": compare_versions(current, latest) if current and latest else None,
    }


async def _adguard_component() -> dict:
    # AdGuard's GitHub tags track its binary/release channel, which can drift
    # from what a given install's /control/status reports — so this pairing
    # is best-effort, and normalize/compare return honest nulls when the two
    # shapes don't line up.
    async def current() -> str | None:
        try:
            async with adguard._client() as client:
                resp = await client.get("/control/status")
                resp.raise_for_status()
                version = resp.json().get("version")
                return str(version) if version else None
        except (httpx.HTTPError, ValueError):
            return None

    current_v, latest = await asyncio.gather(
        current(), _github_latest_tag("AdguardTeam/AdGuardHome")
    )
    return _component_row("adguard", current_v, latest)


async def _github_component(
    name: str, argv: list[str], repo: str, clean: Callable[[str], str] = _first_token
) -> dict:
    current, latest = await asyncio.gather(_cli_current(argv, clean), _github_latest_tag(repo))
    return _component_row(name, current, latest)


async def _apt_component(name: str, pkg: str) -> dict:
    current, latest = await asyncio.gather(_dpkg_current(pkg), _apt_candidate_latest(pkg))
    return _component_row(name, current, latest)


# --- OS layer ------------------------------------------------------------------

async def _os_updates() -> dict:
    summary_count: int | None = None
    packages: list[dict] | None = None
    try:
        sim = await run(["apt-get", "-s", "upgrade"])
        if sim.ok:
            summary_count = parse_upgrade_summary(sim.output)
    except CommandError:
        pass
    try:
        listing = await run(["apt", "list", "--upgradable"])
        if listing.ok:
            packages = parse_upgradable_list(listing.output)
    except CommandError:
        pass
    security_count = None
    if packages is not None:
        security_count = sum(1 for p in packages if p["security"])
        if summary_count is None:
            summary_count = len(packages)
    return {
        "upgradable_count": summary_count,
        "security_count": security_count,
        "packages": packages or [],
    }


# --- endpoint ------------------------------------------------------------------

@router.get("/check")
async def check_updates() -> dict:
    """On-demand freshness sweep: pending OS packages plus every stack
    component's current vs latest version. Installs nothing; the user
    decides. Probes run concurrently, each bounded by SWEEP_TIMEOUT — a hung
    or failing probe reports nulls instead of failing the sweep."""
    probes: list[tuple[str, Awaitable[dict]]] = [
        ("adguard", _adguard_component()),
        (
            "headscale",
            _github_component(
                "headscale",
                [settings.headscale_bin, "version"],
                "juanfont/headscale",
                clean=_clean_headscale,
            ),
        ),
        (
            "tailscale",
            _github_component(
                "tailscale", [settings.tailscale_bin, "version"], "tailscale/tailscale"
            ),
        ),
        (
            "nextdns",
            _github_component(
                "nextdns", [settings.nextdns_bin, "version"], "nextdns/nextdns"
            ),
        ),
        ("unbound", _apt_component("unbound", "unbound")),
        ("ntopng", _apt_component("ntopng", "ntopng")),
    ]

    async def bounded(name: str, probe: Awaitable[dict]) -> dict:
        # A timed-out or buggy probe reports nulls; it must never fail the sweep.
        try:
            return await asyncio.wait_for(probe, timeout=SWEEP_TIMEOUT)
        except Exception:
            return _component_row(name, None, None)

    async def os_bounded() -> dict:
        try:
            return await asyncio.wait_for(_os_updates(), timeout=SWEEP_TIMEOUT)
        except Exception:
            return {"upgradable_count": None, "security_count": None, "packages": []}

    os_info, *components = await asyncio.gather(
        os_bounded(), *(bounded(name, probe) for name, probe in probes)
    )
    return {
        "os": os_info,
        "components": components,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
