"""NextDNS — wrapped via the `nextdns` CLI.

Presented to the app as "Cloud Filtering": NextDNS's cloud-managed blocklists
and analytics, running as a local forwarder on the Pi.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from ..auth import require_token
from ..config import settings
from ..models import ActionResponse, ServiceHealth
from ..runner import CommandError, run

router = APIRouter(prefix="/nextdns", tags=["nextdns"], dependencies=[Depends(require_token)])


async def health() -> ServiceHealth:
    try:
        result = await run([settings.nextdns_bin, "status"])
    except CommandError as exc:
        return ServiceHealth(
            id="nextdns", name="Cloud Filtering", running=False, installed=False, detail=str(exc)
        )
    state = result.output.strip().lower()
    return ServiceHealth(
        id="nextdns", name="Cloud Filtering", running=state == "running", detail=state
    )


@router.get("/status")
async def get_status() -> dict:
    return (await health()).model_dump()


@router.get("/config")
async def get_config() -> dict:
    try:
        result = await run([settings.nextdns_bin, "config"])
    except CommandError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    if not result.ok:
        raise HTTPException(status_code=503, detail=result.output)
    config: dict[str, str] = {}
    for line in result.stdout.splitlines():
        if " " in line:
            key, _, value = line.partition(" ")
            config[key.strip()] = value.strip()
    # Don't leak anything sensitive-looking to the app.
    config.pop("api-key", None)
    return config


@router.post("/activate")
async def activate() -> ActionResponse:
    """Point the system resolver at NextDNS."""
    try:
        result = await run([settings.nextdns_bin, "activate"], timeout=30.0)
    except CommandError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    return ActionResponse(ok=result.ok, message="Cloud filtering on" if result.ok else result.output)


@router.post("/deactivate")
async def deactivate() -> ActionResponse:
    try:
        result = await run([settings.nextdns_bin, "deactivate"], timeout=30.0)
    except CommandError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    return ActionResponse(ok=result.ok, message="Cloud filtering off" if result.ok else result.output)


@router.post("/restart")
async def restart() -> ActionResponse:
    try:
        result = await run([settings.nextdns_bin, "restart"], timeout=30.0)
    except CommandError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    return ActionResponse(ok=result.ok, message="Cloud filtering restarted" if result.ok else result.output)
