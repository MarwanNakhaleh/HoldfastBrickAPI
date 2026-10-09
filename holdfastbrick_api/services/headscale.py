"""Headscale household coordination — wrapped via the `headscale` CLI.

The brick runs a self-hosted Headscale server (Tailscale-compatible) so the
family's phones can reach it from anywhere. Enrolling a phone mints a
single-use preauth key the phone redeems against the brick's coordination
URL. Also serves the household CA certificate (and an Apple .mobileconfig
profile next to it) so phones can trust the server's TLS certificate.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Path as PathParam, Response
from pydantic import BaseModel

from ..auth import require_token
from ..config import settings
from ..models import ActionResponse
from ..runner import CommandError, run, systemd_status

router = APIRouter(prefix="/household", tags=["household"], dependencies=[Depends(require_token)])

FAMILY_USER = "family"
HEADSCALE_UNIT = "headscale"
KEY_EXPIRATION_HOURS = 24
# Outstanding (unused, unexpired) join keys allowed before minting more is
# refused — each one is a 24-hour door into the household tailnet.
ENROLL_OUTSTANDING_KEY_LIMIT = 5
MOBILECONFIG_NAME = "holdfast-household-ca.mobileconfig"

# `headscale nodes delete` may prompt for confirmation on the device. The
# runner has no stdin, so the CLI either reads EOF or eats the timeout —
# either way we point the user at the device CLI instead of hanging.
_CONFIRM_HINTS = ("confirm", "y/n", "yes/no", "abort")
_CONFIRM_HINT_TEXT = (
    "Run 'headscale nodes delete --identifier <id>' on the brick to confirm, "
    "then retry here."
)

# Preauth keys print as a single token, observed on v0.29.4:
#   hskey-auth-<64 mixed-case alphanumerics, with internal dashes>
# Scan for the last key-shaped token in case chatter precedes it.
_PREAUTH_KEY_RE = re.compile(r"\bhskey-auth-[A-Za-z0-9-]+")


def family_user_id(users_json: str) -> int | None:
    """The numeric id of the family user from `users list -o json`, or None.

    `preauthkeys create --user` requires the id, not the name (observed
    v0.29.4: strconv.ParseUint error on a name). Empty tailnets and version
    drift degrade to None, which callers treat as "create the user first".
    """
    try:
        data = json.loads(users_json)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, list):
        return None
    for user in data:
        if isinstance(user, dict) and user.get("name") == FAMILY_USER:
            try:
                return int(user["id"])
            except (KeyError, TypeError, ValueError):
                return None
    return None


# --- pure logic (unit-testable) ----------------------------------------------

def _last_seen_iso(value) -> str:
    """`last_seen` as ISO 8601 UTC. Observed v0.29.4 shape is a protobuf
    timestamp object ({seconds, nanos}); older docs showed ISO strings —
    both are accepted, anything else becomes an empty string."""
    if isinstance(value, dict):
        try:
            seconds = int(value.get("seconds") or 0)
        except (TypeError, ValueError):
            return ""
        if seconds <= 0:
            return ""
        return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()
    if isinstance(value, str):
        return value
    return ""


def parse_nodes_json(text: str) -> list[dict]:
    """Normalized device list from `headscale nodes list -o json`.

    The exact JSON shape drifted across headscale versions (bare list vs
    {"nodes": [...]}, user as object vs string), so every field is coerced
    defensively; anything unparseable becomes an empty list.
    """
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        data = data.get("nodes")
    if not isinstance(data, list):
        return []
    devices = []
    for item in data:
        if not isinstance(item, dict):
            continue
        user = item.get("user")
        if isinstance(user, dict):
            user_name = str(user.get("name") or user.get("username") or "")
        else:
            user_name = str(user or "")
        devices.append(
            {
                "id": str(item.get("id") or ""),
                "name": str(
                    item.get("name") or item.get("hostname") or item.get("machine") or ""
                ),
                "user": user_name,
                # v0.29.4 node objects carry no online flag; presence of a
                # recent last_seen is the honest signal we have.
                "online": bool(item.get("online", False)),
                "last_seen": _last_seen_iso(item.get("lastSeen") or item.get("last_seen")),
            }
        )
    return devices


def extract_preauth_key(output: str) -> str:
    """The preauth key printed by `preauthkeys create`, or "" if none."""
    for line in reversed(output.splitlines()):
        match = _PREAUTH_KEY_RE.search(line)
        if match:
            return match.group(0)
    return ""


def _key_expiration(value) -> datetime | None:
    """`expiration` as an aware UTC datetime, or None when absent/unparseable.

    Observed v0.29.4 shape is the protobuf timestamp object ({seconds,
    nanos}); ISO strings are accepted for version drift. Callers treat None
    as "unknown, assume outstanding" — the safe direction for a cap."""
    if isinstance(value, dict):
        try:
            seconds = int(value.get("seconds") or 0)
        except (TypeError, ValueError):
            return None
        if seconds <= 0:
            return None
        return datetime.fromtimestamp(seconds, tz=timezone.utc)
    if isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return None


def count_unused_preauth_keys(keys_json: str, user_id: int, now: datetime) -> int | None:
    """Unused, unexpired preauth keys belonging to the family user.

    Returns None when the listing can't be understood at all — the caller
    then skips the cap rather than failing enrollment over it. A key whose
    expiration is missing/unparseable still counts (assume outstanding).
    """
    try:
        data = json.loads(keys_json)
    except json.JSONDecodeError:
        return None
    if data is None:  # observed v0.29.4: an empty listing prints bare `null`
        return 0
    if isinstance(data, dict):
        data = data.get("preAuthKeys")
    if not isinstance(data, list):
        return None
    outstanding = 0
    for item in data:
        if not isinstance(item, dict):
            continue
        user = item.get("user")
        if isinstance(user, dict):
            user_value = user.get("id")
        else:
            user_value = user
        try:
            if int(user_value) != user_id:
                continue
        except (TypeError, ValueError):
            continue
        if bool(item.get("used", False)):
            continue
        expiration = _key_expiration(item.get("expiration"))
        if expiration is not None and expiration <= now:
            continue
        outstanding += 1
    return outstanding


# --- availability probing -----------------------------------------------------

async def _probe() -> tuple[bool, bool]:
    """(installed, running) — never raises. installed = CLI answers `version`."""
    try:
        result = await run([settings.headscale_bin, "version"])
    except CommandError:
        return False, False
    if not result.ok:
        return False, False
    try:
        status = await systemd_status(HEADSCALE_UNIT)
    except CommandError:
        return True, False
    return True, bool(status["running"])


def _unavailable_detail(installed: bool) -> str:
    if not installed:
        return (
            "Headscale isn't installed on this brick yet. Run provisioning, "
            "then retry."
        )
    return (
        f"The {HEADSCALE_UNIT} service isn't running. Start it on the brick "
        f"('sudo systemctl start {HEADSCALE_UNIT}'), then retry."
    )


async def _list_nodes() -> list[dict]:
    try:
        result = await run([settings.headscale_bin, "nodes", "list", "-o", "json"])
    except CommandError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if not result.ok:
        raise HTTPException(status_code=503, detail=result.output or "nodes list failed")
    return parse_nodes_json(result.stdout)


# --- endpoints ----------------------------------------------------------------

@router.get("/status")
async def get_status() -> dict:
    """Headscale availability + the devices enrolled on the household."""
    installed, running = await _probe()
    devices: list[dict] = []
    if installed and running:
        try:
            result = await run([settings.headscale_bin, "nodes", "list", "-o", "json"])
            if result.ok:
                devices = parse_nodes_json(result.stdout)
        except CommandError:
            pass
    return {
        "available": installed and running,
        "running": running,
        "url": settings.headscale_url,
        "device_count": len(devices),
        "devices": devices,
    }


class EnrollRequest(BaseModel):
    device_name: str = ""


async def _family_user_id() -> int:
    """The family user's numeric id, creating the user if absent.

    `preauthkeys create --user` rejects names (it wants the id), so the JSON
    listing is the lookup; a create is followed by a re-list because the
    create output does not carry the id either.
    """
    async def _lookup() -> int | None:
        try:
            result = await run(
                [settings.headscale_bin, "users", "list", "-o", "json"]
            )
        except CommandError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        if not result.ok:
            raise HTTPException(
                status_code=502, detail=result.output or "couldn't list Headscale users"
            )
        return family_user_id(result.stdout)

    existing = await _lookup()
    if existing is not None:
        return existing
    try:
        result = await run([settings.headscale_bin, "users", "create", FAMILY_USER])
    except CommandError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if not result.ok:
        combined = f"{result.stdout}\n{result.stderr}".lower()
        if "already exists" not in combined:
            raise HTTPException(
                status_code=502, detail=result.output or "couldn't create the family user"
            )
    created = await _lookup()
    if created is None:
        raise HTTPException(
            status_code=502,
            detail="family user is missing even after creation — check 'headscale users list' on the brick",
        )
    return created


@router.post("/enroll")
async def enroll(body: EnrollRequest | None = None) -> dict:
    """Mint a single-use preauth key so one phone can join the household.

    Capped at ENROLL_OUTSTANDING_KEY_LIMIT unused, unexpired keys: each
    outstanding key is a standing invitation into the household, so the
    user is told to revoke or wait for expiry. If the key listing itself
    can't be read, the cap is skipped — enrollment must not break over
    housekeeping."""
    installed, running = await _probe()
    if not (installed and running):
        raise HTTPException(status_code=503, detail=_unavailable_detail(installed))
    user_id = await _family_user_id()
    try:
        listing = await run(
            [settings.headscale_bin, "preauthkeys", "list", "-o", "json"]
        )
    except CommandError:
        listing = None
    if listing is not None and listing.ok:
        outstanding = count_unused_preauth_keys(
            listing.stdout, user_id, datetime.now(timezone.utc)
        )
        if outstanding is not None and outstanding >= ENROLL_OUTSTANDING_KEY_LIMIT:
            raise HTTPException(
                status_code=429,
                detail=(
                    f"This household already has {outstanding} unused join keys "
                    "waiting. Revoke or wait for expiry before minting another."
                ),
            )
    try:
        result = await run(
            [
                settings.headscale_bin,
                "preauthkeys",
                "create",
                "--user",
                str(user_id),
                "--expiration",
                f"{KEY_EXPIRATION_HOURS}h",
            ]
        )
    except CommandError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if not result.ok:
        raise HTTPException(
            status_code=502, detail=result.output or "couldn't create a preauth key"
        )
    auth_key = extract_preauth_key(result.stdout)
    if not auth_key:
        raise HTTPException(
            status_code=502, detail="preauthkeys create didn't print a usable key"
        )
    expires_at = datetime.now(timezone.utc) + timedelta(hours=KEY_EXPIRATION_HOURS)
    return {
        "server_url": settings.headscale_url,
        "auth_key": auth_key,
        "expires_at": expires_at.isoformat(),
    }


@router.get("/devices")
async def get_devices() -> dict:
    devices = await _list_nodes()
    return {"device_count": len(devices), "devices": devices}


@router.post("/devices/{node_id}/remove")
async def remove_device(node_id: int = PathParam(gt=0)) -> ActionResponse:
    """Remove an enrolled device. --force disables the CLI's y/n prompt
    (observed v0.29.4: without it the CLI reads EOF, prints "Node not
    deleted", and exits 0 — a silent no-op that must never look like
    success here)."""
    try:
        result = await run(
            [
                settings.headscale_bin,
                "nodes",
                "delete",
                "--identifier",
                str(node_id),
                "--force",
            ]
        )
    except CommandError as exc:
        if "timed out" in str(exc):
            raise HTTPException(
                status_code=409,
                detail=f"Headscale is waiting for confirmation on the device. {_CONFIRM_HINT_TEXT}",
            ) from exc
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if result.ok:
        return ActionResponse(ok=True, message="Device removed from the household network.")
    combined = f"{result.stdout}\n{result.stderr}".lower()
    if any(hint in combined for hint in _CONFIRM_HINTS):
        raise HTTPException(
            status_code=409,
            detail=f"Headscale asked for confirmation on the device. {_CONFIRM_HINT_TEXT}",
        )
    raise HTTPException(status_code=502, detail=result.output or "nodes delete failed")


@router.get("/ca")
async def get_ca() -> Response:
    try:
        content = Path(settings.headscale_ca_cert).read_bytes()
    except OSError:
        raise HTTPException(
            status_code=404,
            detail=(
                "The household CA certificate isn't on this brick yet — "
                "run provisioning first."
            ),
        )
    return Response(content=content, media_type="application/x-x509-ca-cert")


@router.get("/ca/profile")
async def get_ca_profile() -> Response:
    path = Path(settings.headscale_ca_cert).with_name(MOBILECONFIG_NAME)
    try:
        content = path.read_bytes()
    except OSError:
        raise HTTPException(
            status_code=404,
            detail=(
                "The household CA profile isn't on this brick yet — "
                "run provisioning first."
            ),
        )
    return Response(content=content, media_type="application/x-apple-aspen-config")
