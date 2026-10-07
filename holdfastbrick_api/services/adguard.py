"""AdGuard Home — proxied via its local REST API (http://127.0.0.1:3000).

Presented to the app as "Ad Blocking". The API credentials are the AdGuard
Home admin credentials, configured in /etc/holdfastbrick/.env at install time;
the phone never sees them.
"""

from __future__ import annotations

from typing import Literal

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..auth import require_token
from ..config import settings
from ..models import ActionResponse, ServiceHealth

router = APIRouter(prefix="/adguard", tags=["adguard"], dependencies=[Depends(require_token)])


def _client() -> httpx.AsyncClient:
    auth = None
    if settings.adguard_username:
        auth = (settings.adguard_username, settings.adguard_password)
    return httpx.AsyncClient(base_url=settings.adguard_url, auth=auth, timeout=10.0)


_CREDENTIALS_HINT = (
    "Set HOLDFASTBRICK_ADGUARD_USERNAME and HOLDFASTBRICK_ADGUARD_PASSWORD in "
    "/etc/holdfastbrick/.env on the device (the AdGuard Home admin login), "
    "then run 'sudo systemctl restart holdfastbrick-api'."
)


def _proxy_error(exc: httpx.HTTPError) -> HTTPException:
    """Translate an AdGuard proxy failure into something actionable.

    A 401/403 from AdGuard is a credentials problem, not an availability
    problem — calling it "unreachable" sends the user hunting in the wrong
    direction."""
    if isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code in (401, 403):
        problem = (
            "AdGuard Home rejected the configured admin credentials"
            if settings.adguard_username
            else "AdGuard Home requires its admin credentials, which aren't configured yet"
        )
        return HTTPException(status_code=502, detail=f"{problem}. {_CREDENTIALS_HINT}")
    return HTTPException(status_code=503, detail=f"AdGuard Home unreachable: {exc}")


async def health() -> ServiceHealth:
    try:
        async with _client() as client:
            resp = await client.get("/control/status")
            resp.raise_for_status()
            data = resp.json()
        return ServiceHealth(
            id="adguard",
            name="Ad Blocking",
            running=data.get("running", False) and data.get("protection_enabled", False),
            detail="protecting" if data.get("protection_enabled") else "paused",
        )
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code in (401, 403):
            # Installed and answering — it just needs credentials.
            return ServiceHealth(
                id="adguard", name="Ad Blocking", running=False,
                detail="needs AdGuard admin credentials in /etc/holdfastbrick/.env",
            )
        return ServiceHealth(id="adguard", name="Ad Blocking", running=False, installed=False, detail=str(exc))
    except httpx.HTTPError as exc:
        return ServiceHealth(id="adguard", name="Ad Blocking", running=False, installed=False, detail=str(exc))


@router.get("/status")
async def get_status() -> dict:
    try:
        async with _client() as client:
            resp = await client.get("/control/status")
            resp.raise_for_status()
            return resp.json()
    except httpx.HTTPError as exc:
        raise _proxy_error(exc) from exc


@router.get("/stats")
async def get_stats() -> dict:
    """Friendly stats: queries today, ads blocked, percent blocked, top blocked."""
    try:
        async with _client() as client:
            resp = await client.get("/control/stats")
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPError as exc:
        raise _proxy_error(exc) from exc
    total = data.get("num_dns_queries", 0)
    blocked = data.get("num_blocked_filtering", 0)
    return {
        "total_queries": total,
        "blocked": blocked,
        "blocked_percent": round(100 * blocked / total, 1) if total else 0.0,
        "avg_processing_ms": data.get("avg_processing_time", 0) * 1000,
        "top_blocked_domains": data.get("top_blocked_domains", []),
        "top_clients": data.get("top_clients", []),
    }


class ProtectionRequest(BaseModel):
    enabled: bool


@router.post("/protection")
async def set_protection(body: ProtectionRequest) -> ActionResponse:
    """The big friendly on/off switch for ad blocking."""
    try:
        async with _client() as client:
            resp = await client.post("/control/protection", json={"enabled": body.enabled})
            resp.raise_for_status()
    except httpx.HTTPError as exc:
        raise _proxy_error(exc) from exc
    return ActionResponse(
        ok=True, message="Ad blocking on" if body.enabled else "Ad blocking paused"
    )


@router.get("/querylog")
async def get_querylog(limit: int = 50, search: str | None = None) -> dict:
    """Recent DNS queries, reshaped for the app's activity feed."""
    params: dict = {"limit": limit}
    if search:
        params["search_question_string"] = search
    try:
        async with _client() as client:
            resp = await client.get("/control/querylog", params=params)
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPError as exc:
        raise _proxy_error(exc) from exc
    entries = []
    for item in data.get("data", []):
        reason = item.get("reason", "")
        entries.append(
            {
                "domain": (item.get("question") or {}).get("name", ""),
                "client": item.get("client", ""),
                "time": item.get("time", ""),
                # "FilteredBlackList", "FilteredSafeBrowsing", ... mean blocked;
                # "NotFilteredNotFound" etc. do not.
                "blocked": reason.startswith("Filtered") and not reason.startswith("NotFiltered"),
                "reason": reason,
            }
        )
    return {"entries": entries}


@router.get("/blocklists")
async def get_blocklists() -> dict:
    try:
        async with _client() as client:
            resp = await client.get("/control/filtering/status")
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPError as exc:
        raise _proxy_error(exc) from exc
    return {
        "blocklists": [
            {
                "id": f.get("id", 0),
                "name": f.get("name", ""),
                "url": f.get("url", ""),
                "enabled": f.get("enabled", False),
                "rules_count": f.get("rules_count", 0),
            }
            for f in data.get("filters") or []
        ]
    }


class BlocklistAddRequest(BaseModel):
    url: str
    name: str


@router.post("/blocklists")
async def add_blocklist(body: BlocklistAddRequest) -> ActionResponse:
    try:
        async with _client() as client:
            resp = await client.post(
                "/control/filtering/add_url",
                json={"url": body.url, "name": body.name, "whitelist": False},
            )
            resp.raise_for_status()
    except httpx.HTTPError as exc:
        raise _proxy_error(exc) from exc
    return ActionResponse(ok=True, message=f"Blocklist '{body.name}' added")


class BlocklistRemoveRequest(BaseModel):
    url: str


@router.post("/blocklists/remove")
async def remove_blocklist(body: BlocklistRemoveRequest) -> ActionResponse:
    try:
        async with _client() as client:
            resp = await client.post(
                "/control/filtering/remove_url",
                json={"url": body.url, "whitelist": False},
            )
            resp.raise_for_status()
    except httpx.HTTPError as exc:
        raise _proxy_error(exc) from exc
    return ActionResponse(ok=True, message="Blocklist removed")


# Conservative: labels of letters/digits/hyphens joined by dots. No scheme, no
# slashes, no leading/trailing hyphens — anything else is rejected with a 422.
_DOMAIN_PATTERN = (
    r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$"
)


class RuleRequest(BaseModel):
    domain: str = Field(..., max_length=253, pattern=_DOMAIN_PATTERN)
    action: Literal["allow", "deny"]


@router.post("/rules")
async def add_rule(body: RuleRequest) -> ActionResponse:
    """Allow or block a single domain via AdGuard Home's custom user rules."""
    rule = f"@@||{body.domain}^" if body.action == "allow" else f"||{body.domain}^"
    try:
        async with _client() as client:
            resp = await client.get("/control/filtering/status")
            resp.raise_for_status()
            rules = list(resp.json().get("user_rules") or [])
            if rule not in rules:
                rules.append(rule)
                resp = await client.post("/control/filtering/set_rules", json={"rules": rules})
                resp.raise_for_status()
    except httpx.HTTPError as exc:
        raise _proxy_error(exc) from exc
    verb = "allowed" if body.action == "allow" else "blocked"
    return ActionResponse(ok=True, message=f"{body.domain} {verb}")
