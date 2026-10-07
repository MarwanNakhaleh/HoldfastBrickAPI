"""Encrypted DNS status.

Presented to the app as "Encrypted DNS". With the provisioned stack this is
unbound itself, which forwards over DNS-over-TLS; a dedicated proxy unit
(e.g. https-dns-proxy) also works. We report the configured unit's health.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from ..auth import require_token
from ..config import settings
from ..models import ActionResponse, ServiceHealth
from ..runner import CommandError, systemd_action, systemd_status

router = APIRouter(prefix="/doh", tags=["doh"], dependencies=[Depends(require_token)])


async def health() -> ServiceHealth:
    if not settings.doh_service_unit:
        return ServiceHealth(
            id="doh", name="Encrypted DNS", running=False, installed=False,
            detail="no DoH unit configured",
        )
    try:
        status = await systemd_status(settings.doh_service_unit)
        return ServiceHealth(
            id="doh", name="Encrypted DNS", running=status["running"], detail=status["state"]
        )
    except CommandError as exc:
        return ServiceHealth(
            id="doh", name="Encrypted DNS", running=False, installed=False, detail=str(exc)
        )


@router.get("/status")
async def get_status() -> dict:
    return (await health()).model_dump()


@router.post("/restart")
async def restart() -> ActionResponse:
    if not settings.doh_service_unit:
        raise HTTPException(status_code=404, detail="No DoH service configured")
    try:
        result = await systemd_action(settings.doh_service_unit, "restart")
    except CommandError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    return ActionResponse(ok=result.ok, message="Encrypted DNS restarted" if result.ok else result.output)
