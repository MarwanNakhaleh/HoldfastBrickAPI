"""ntopng — proxied via its local REST API.

Presented to the app as "Network Monitor": who's on the network and how much
they're talking. Only a small, curated slice of ntopng's API is exposed.
"""

from __future__ import annotations

import httpx
from fastapi import APIRouter, Depends, HTTPException

from ..auth import require_token
from ..config import settings
from ..models import ServiceHealth
from ..runner import CommandError, systemd_status

router = APIRouter(prefix="/ntopng", tags=["ntopng"], dependencies=[Depends(require_token)])


def _client() -> httpx.AsyncClient:
    headers = {}
    if settings.ntopng_token:
        headers["Authorization"] = f"Token {settings.ntopng_token}"
    return httpx.AsyncClient(base_url=settings.ntopng_url, headers=headers, timeout=10.0)


async def health() -> ServiceHealth:
    try:
        status = await systemd_status("ntopng")
        return ServiceHealth(
            id="ntopng", name="Network Monitor", running=status["running"], detail=status["state"]
        )
    except CommandError as exc:
        return ServiceHealth(
            id="ntopng", name="Network Monitor", running=False, installed=False, detail=str(exc)
        )


@router.get("/status")
async def get_status() -> dict:
    return (await health()).model_dump()


@router.get("/hosts")
async def get_hosts(interface: int = 0) -> dict:
    """Active devices on the network, friendliest-possible shape."""
    try:
        async with _client() as client:
            resp = await client.get(
                "/lua/rest/v2/get/host/active.lua", params={"ifid": interface}
            )
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail=f"ntopng unreachable: {exc}")
    hosts = data.get("rsp", {}).get("data", []) if isinstance(data.get("rsp"), dict) else data.get("rsp", [])
    return {
        "hosts": [
            {
                "ip": h.get("ip", ""),
                "name": h.get("name", "") or h.get("ip", ""),
                "bytes_sent": h.get("bytes_sent", 0),
                "bytes_received": h.get("bytes_rcvd", 0),
                "active_flows": h.get("active_flows", 0),
            }
            for h in hosts
            if isinstance(h, dict)
        ]
    }


@router.get("/interface-stats")
async def get_interface_stats(interface: int = 0) -> dict:
    try:
        async with _client() as client:
            resp = await client.get("/lua/rest/v2/get/interface/data.lua", params={"ifid": interface})
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail=f"ntopng unreachable: {exc}")
    rsp = data.get("rsp", {})
    return {
        "throughput_bps": rsp.get("throughput_bps", 0),
        "bytes": rsp.get("bytes", 0),
        "packets": rsp.get("packets", 0),
        "num_hosts": rsp.get("num_hosts", 0),
        "num_flows": rsp.get("num_flows", 0),
    }
