"""Holdfast API entry point.

Runs on the Pi itself (see deploy/holdfastbrick-api.service). The iOS app
discovers it via Bonjour (_holdfastbrick._tcp), pairs once with a 6-digit
code, then talks to it directly over the LAN — or from anywhere via
Tailscale. There is no cloud component.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket

from fastapi import Depends, FastAPI, HTTPException

from . import __version__
from .auth import require_token, try_pair
from .config import settings
from .models import IdentityResponse, OverviewResponse, PairRequest, PairResponse
from .services import adguard, dhcp, doh, nextdns, ntopng, system, tailscale, unbound

try:
    from zeroconf import ServiceInfo
    from zeroconf.asyncio import AsyncZeroconf
except ImportError:  # zeroconf is optional in dev environments
    ServiceInfo = None  # type: ignore[assignment]
    AsyncZeroconf = None  # type: ignore[assignment]


def _local_ip() -> str:
    # Address used for the default route; never actually sends packets.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.connect(("10.255.255.255", 1))
            return sock.getsockname()[0]
        except OSError:
            return "127.0.0.1"


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    aiozc = None
    if settings.mdns_enabled and AsyncZeroconf is not None:
        info = ServiceInfo(
            settings.mdns_service_type,
            f"{settings.device_name}.{settings.mdns_service_type}",
            addresses=[socket.inet_aton(_local_ip())],
            port=settings.port,
            properties={"version": __version__, "name": settings.device_name},
        )
        aiozc = AsyncZeroconf()
        await aiozc.async_register_service(info)
        app.state.mdns_info = info
    yield
    if aiozc is not None:
        await aiozc.async_unregister_service(app.state.mdns_info)
        await aiozc.async_close()


app = FastAPI(
    title="Holdfast API",
    version=__version__,
    description="Local control plane for a Holdfast Brick (Raspberry Pi DNS privacy appliance).",
    lifespan=lifespan,
)

API = "/api/v1"
for service_router in (
    unbound.router,
    doh.router,
    tailscale.router,
    adguard.router,
    dhcp.router,
    nextdns.router,
    ntopng.router,
    system.router,
):
    app.include_router(service_router, prefix=API)


@app.get(f"{API}/ping")
async def ping() -> dict:
    """Unauthenticated liveness + identity check, used during discovery."""
    return {"app": "holdfastbrick", "version": __version__, "device_name": settings.device_name}


@app.post(f"{API}/pair", response_model=PairResponse)
async def pair(body: PairRequest) -> PairResponse:
    token = try_pair(body.code, body.client_name)
    if token is None:
        raise HTTPException(
            status_code=403,
            detail="Wrong or expired code. Run 'holdfastbrick-pair' on the device for a new one.",
        )
    return PairResponse(token=token, device_name=settings.device_name)


@app.get(
    f"{API}/identity",
    response_model=IdentityResponse,
    dependencies=[Depends(require_token)],
)
async def get_identity() -> IdentityResponse:
    """Where to reach this device — the app uses the Tailscale address for
    remote access. Degrades gracefully when Tailscale is absent or down."""
    tailscale_ips, magicdns_name = await tailscale.identity()
    return IdentityResponse(
        device_name=settings.device_name,
        version=__version__,
        port=settings.port,
        lan_ip=_local_ip(),
        tailscale_ips=tailscale_ips,
        magicdns_name=magicdns_name,
    )


@app.get(
    f"{API}/overview",
    response_model=OverviewResponse,
    dependencies=[Depends(require_token)],
)
async def get_overview() -> OverviewResponse:
    """Single call powering the app's home screen."""
    results = await asyncio.gather(
        adguard.health(),
        unbound.health(),
        doh.health(),
        tailscale.health(),
        nextdns.health(),
        ntopng.health(),
        system.health(),
        return_exceptions=True,
    )
    services = [r for r in results if not isinstance(r, BaseException)]
    # "Protected" = the two core protection layers are up.
    by_id = {s.id: s for s in services}
    protected = bool(
        by_id.get("adguard") and by_id["adguard"].running
        and by_id.get("unbound") and by_id["unbound"].running
    )
    return OverviewResponse(
        device_name=settings.device_name, protected=protected, services=services
    )


def main() -> None:
    import uvicorn

    uvicorn.run(app, host=settings.host, port=settings.port)


if __name__ == "__main__":
    main()
