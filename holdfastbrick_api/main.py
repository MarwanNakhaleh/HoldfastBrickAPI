"""Holdfast API entry point.

Runs on the Pi itself (see deploy/holdfastbrick-api.service). The iOS app
discovers it via Bonjour (_holdfastbrick._tcp), pairs once with a 6-digit
code, then talks to it directly over the LAN — or from anywhere via
Tailscale. There is no cloud component.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import socket

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse

from . import __version__
from .auth import pair_attempt_allowed, require_token, router as auth_router, try_pair
from .config import cert_fingerprint, settings
from .models import IdentityResponse, OverviewResponse, PairRequest, PairResponse
from .services import adguard, dhcp, doh, headscale, network, nextdns, ntopng, system, tailscale, unbound, updates

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


# --- DNS-rebinding guard (pure decision, table-tested) ------------------------

def classify_host(host: str, allowed: list[str] | None = None) -> bool:
    """True when a Host header value may address the brick.

    Allowed: an empty Host (HTTP/1.0 clients), localhost and the loopback
    literals, any literal IPv4/IPv6 address (LAN and tailnet 100.x alike),
    Bonjour-style *.local names, MagicDNS *.ts.net names, and exact extra
    entries from HOLDFASTBRICK_ALLOWED_HOSTS. A public hostname is refused:
    a web page on evil.com must not be able to script this API through a
    victim's browser (DNS rebinding).
    """
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return True
    if host.startswith("["):  # bracketed IPv6, possibly with :port
        host = host[1 : host.index("]")] if "]" in host else host[1:]
    elif host.count(":") == 1:  # a single colon is a port separator, never IPv6
        host = host.split(":", 1)[0]
    if not host:
        return True
    if host in ("localhost", "127.0.0.1", "::1"):
        return True
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    if host.endswith(".local") or host.endswith(".ts.net"):
        return True
    extras = {
        entry.strip().lower().rstrip(".")
        for entry in (allowed or [])
        if entry.strip()
    }
    return host in extras


def _mdns_properties() -> dict:
    """Bonjour TXT record. 'tls': '1' tells phones to expect HTTPS and to
    expect a certificate fingerprint in /ping and /pair."""
    properties = {"version": __version__, "name": settings.device_name}
    if settings.tls_enabled():
        properties["tls"] = "1"
    return properties


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    aiozc = None
    if settings.mdns_enabled and AsyncZeroconf is not None:
        info = ServiceInfo(
            settings.mdns_service_type,
            f"{settings.device_name}.{settings.mdns_service_type}",
            addresses=[socket.inet_aton(_local_ip())],
            port=settings.port,
            properties=_mdns_properties(),
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
    # No interactive docs on the device: /docs, /redoc and /openapi.json were
    # an unauthenticated map of the entire attack surface.
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

API = "/api/v1"


@app.middleware("http")
async def reject_foreign_hosts(request: Request, call_next) -> Response:
    host = request.headers.get("host", "")
    extras = [entry for entry in settings.allowed_hosts.split(",") if entry.strip()]
    if not classify_host(host, extras):
        return JSONResponse(
            status_code=400,
            content={
                "detail": (
                    "That address doesn't belong to this brick. Use the "
                    "Holdfast app, or the brick's local or tailnet address."
                )
            },
        )
    return await call_next(request)


for service_router in (
    auth_router,
    unbound.router,
    doh.router,
    tailscale.router,
    adguard.router,
    dhcp.router,
    network.router,
    headscale.router,
    nextdns.router,
    ntopng.router,
    system.router,
    updates.router,
):
    app.include_router(service_router, prefix=API)


@app.get(f"{API}/ping")
async def ping() -> dict:
    """Unauthenticated liveness + identity check, used during discovery."""
    return {
        "app": "holdfastbrick",
        "version": __version__,
        "device_name": settings.device_name,
        "cert_fingerprint": cert_fingerprint(),
    }


@app.post(f"{API}/pair", response_model=PairResponse)
async def pair(body: PairRequest, request: Request) -> PairResponse:
    source_ip = request.client.host if request.client else ""
    if not pair_attempt_allowed(source_ip):
        raise HTTPException(
            status_code=429,
            detail=(
                "Too many pairing attempts from your address. Wait a minute "
                "and try again."
            ),
        )
    token = try_pair(body.code, body.client_name)
    if token is None:
        raise HTTPException(
            status_code=403,
            detail="Wrong or expired code. Run 'holdfastbrick-pair' on the device for a new one.",
        )
    return PairResponse(
        token=token,
        device_name=settings.device_name,
        cert_fingerprint=cert_fingerprint(),
    )


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

    kwargs: dict = {}
    if settings.tls_enabled():
        kwargs = {
            "ssl_certfile": str(settings.tls_cert),
            "ssl_keyfile": str(settings.tls_key),
        }
        print(
            f"holdfastbrick-api: HTTPS on port {settings.port} "
            f"(certificate {settings.tls_cert})"
        )
    else:
        print(
            f"holdfastbrick-api: plain HTTP on port {settings.port} "
            "(TLS disabled or certificate files missing)"
        )
    uvicorn.run(app, host=settings.host, port=settings.port, **kwargs)


if __name__ == "__main__":
    main()
