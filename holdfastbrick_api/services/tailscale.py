"""Tailscale — wrapped via the `tailscale` CLI (JSON output).

Presented to the app as "Remote Access": lets the user reach their
Holdfast Brick (and use its DNS filtering) securely from anywhere.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException

from ..auth import require_token
from ..config import settings
from ..models import ActionResponse, ServiceHealth
from ..runner import CommandError, run

router = APIRouter(prefix="/tailscale", tags=["tailscale"], dependencies=[Depends(require_token)])


async def health() -> ServiceHealth:
    try:
        result = await run([settings.tailscale_bin, "status", "--json"])
    except CommandError as exc:
        return ServiceHealth(
            id="tailscale", name="Remote Access", running=False, installed=False, detail=str(exc)
        )
    if not result.ok:
        return ServiceHealth(id="tailscale", name="Remote Access", running=False, detail=result.output)
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return ServiceHealth(id="tailscale", name="Remote Access", running=False, detail="unparseable status")
    backend_state = data.get("BackendState", "Unknown")
    return ServiceHealth(
        id="tailscale",
        name="Remote Access",
        running=backend_state == "Running",
        detail=backend_state,
    )


async def identity() -> tuple[list[str], str]:
    """Best-effort (tailscale_ips, magicdns_name) for `/identity`.

    Never raises — when Tailscale is missing, down, or unparseable the app
    simply gets no remote address and falls back to the LAN.
    """
    try:
        result = await run([settings.tailscale_bin, "status", "--json"])
        if not result.ok:
            return [], ""
        data = json.loads(result.stdout)
    except (CommandError, json.JSONDecodeError):
        return [], ""
    self_info = data.get("Self") or {}
    ips = [str(ip) for ip in self_info.get("TailscaleIPs") or []]
    name = str(self_info.get("DNSName") or data.get("MagicDNSSuffix") or "").rstrip(".")
    return ips, name


@router.get("/status")
async def get_status() -> dict:
    try:
        result = await run([settings.tailscale_bin, "status", "--json"])
    except CommandError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    if not result.ok:
        raise HTTPException(status_code=503, detail=result.output)
    data = json.loads(result.stdout)
    self_info = data.get("Self", {})
    peers = data.get("Peer", {}) or {}
    return {
        "state": data.get("BackendState", "Unknown"),
        "hostname": self_info.get("HostName", ""),
        "tailscale_ips": self_info.get("TailscaleIPs", []),
        "magic_dns_suffix": data.get("MagicDNSSuffix", ""),
        "peers": [
            {
                "hostname": p.get("HostName", ""),
                "os": p.get("OS", ""),
                "online": p.get("Online", False),
                "ips": p.get("TailscaleIPs", []),
            }
            for p in peers.values()
        ],
    }


@router.post("/up")
async def up() -> ActionResponse:
    try:
        result = await run([settings.tailscale_bin, "up"], timeout=60.0)
    except CommandError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    # `tailscale up` may print an auth URL when the node isn't logged in yet.
    message = "Remote access enabled" if result.ok else result.output
    return ActionResponse(ok=result.ok, message=message)


@router.post("/down")
async def down() -> ActionResponse:
    try:
        result = await run([settings.tailscale_bin, "down"], timeout=60.0)
    except CommandError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    return ActionResponse(ok=result.ok, message="Remote access paused" if result.ok else result.output)
