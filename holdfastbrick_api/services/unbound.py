"""Unbound recursive DNS resolver — wrapped via `unbound-control`.

Presented to the app as "Private DNS": the piece that resolves names locally
instead of handing every lookup to the ISP.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from ..auth import require_token
from ..config import settings
from ..models import ActionResponse, ServiceHealth
from ..runner import CommandError, run, systemd_action, systemd_status

router = APIRouter(prefix="/unbound", tags=["unbound"], dependencies=[Depends(require_token)])


async def health() -> ServiceHealth:
    try:
        status = await systemd_status("unbound")
        return ServiceHealth(
            id="unbound", name="Private DNS", running=status["running"], detail=status["state"]
        )
    except CommandError as exc:
        return ServiceHealth(
            id="unbound", name="Private DNS", running=False, installed=False, detail=str(exc)
        )


def _parse_stats(raw: str) -> dict[str, float]:
    stats: dict[str, float] = {}
    for line in raw.splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            try:
                stats[key.strip()] = float(value.strip())
            except ValueError:
                continue
    return stats


@router.get("/status")
async def get_status() -> dict:
    return (await health()).model_dump()


@router.get("/stats")
async def get_stats() -> dict:
    """Friendly stats: total queries, cache hit rate, average response time."""
    try:
        result = await run([settings.unbound_control_bin, "stats_noreset"])
    except CommandError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    if not result.ok:
        raise HTTPException(status_code=503, detail=result.output)
    stats = _parse_stats(result.stdout)
    total = stats.get("total.num.queries", 0)
    hits = stats.get("total.num.cachehits", 0)
    return {
        "total_queries": int(total),
        "cache_hits": int(hits),
        "cache_hit_rate": round(hits / total, 4) if total else 0.0,
        "avg_response_ms": round(stats.get("total.recursion.time.avg", 0) * 1000, 1),
        "raw": stats,
    }


@router.post("/flush-cache")
async def flush_cache() -> ActionResponse:
    try:
        result = await run([settings.unbound_control_bin, "flush_zone", "."])
    except CommandError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    return ActionResponse(ok=result.ok, message="DNS cache cleared" if result.ok else result.output)


@router.post("/restart")
async def restart() -> ActionResponse:
    try:
        result = await systemd_action("unbound", "restart")
    except CommandError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    return ActionResponse(ok=result.ok, message="Private DNS restarted" if result.ok else result.output)
