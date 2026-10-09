"""Pairing + bearer-token authentication.

Flow (designed so a non-technical user never types an IP address):

1. The Pi advertises itself over mDNS/Bonjour; the iOS app finds it.
2. The user (or the install script) opens a pairing window by running
   ``holdfastbrick-pair`` on the Pi, which prints a 6-digit code. The install
   script also opens a window automatically on first boot so onboarding is
   just "enter the code from the sticker/screen".
3. The app POSTs the code to ``/api/v1/pair`` and receives a long-lived
   bearer token, stored in the iOS Keychain.
4. Every other endpoint requires ``Authorization: Bearer <token>``.

Hardening: five wrong codes wipe the pairing window (run
``holdfastbrick-pair`` again), pairing attempts are rate-limited per source
address, and tokens can be listed and revoked via ``/auth/tokens``.
"""

from __future__ import annotations

import hashlib
import secrets
import time
from collections import deque

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .config import settings, state
from .models import TokenInfo

_bearer = HTTPBearer(auto_error=False)

# Wrong codes allowed before the pairing window is wiped entirely. The
# counter is persisted in state, so it survives API restarts.
MAX_PAIRING_FAILURES = 5

# Per-source-address attempts within a sliding window, shared by the gates
# that guard 6-digit codes (pairing, SSH-key confirmation). In-memory on
# purpose: holdfastbrick-api.service runs a single worker, so this process
# sees all traffic. If the service ever runs multiple workers, this must
# move into shared state or the limit silently multiplies.
CODED_GATE_LIMIT = 10
CODED_GATE_WINDOW_SECONDS = 60.0

_gate_attempts: dict[str, deque[float]] = {}


def sliding_window_allowed(bucket: str, now: float | None = None) -> bool:
    """True unless ``bucket`` (a gate name plus source address) already made
    CODED_GATE_LIMIT attempts within the last CODED_GATE_WINDOW_SECONDS.
    Counts every attempt, right or wrong, so a window can't be ground down
    cheaply."""
    now = time.time() if now is None else now
    attempts = _gate_attempts.setdefault(bucket, deque())
    while attempts and now - attempts[0] > CODED_GATE_WINDOW_SECONDS:
        attempts.popleft()
    if len(attempts) >= CODED_GATE_LIMIT:
        return False
    attempts.append(now)
    return True


def pair_attempt_allowed(source_ip: str, now: float | None = None) -> bool:
    """Pairing gate: the sliding window on /pair, per source address."""
    return sliding_window_allowed(f"pair:{source_ip}", now)


def open_pairing_window() -> str:
    """Open a pairing window and return the 6-digit code. A fresh window
    starts with a clean failure slate; the window itself is the physical
    presence gate."""
    code = f"{secrets.randbelow(1_000_000):06d}"
    state.clear_pairing_failures()
    state.set_pairing(code, time.time() + settings.pairing_window_seconds)
    return code


def try_pair(code: str, client_name: str) -> str | None:
    """Exchange a valid pairing code for a bearer token, else None.

    MAX_PAIRING_FAILURES wrong codes clear the window: the correct code
    stops working too, and a new one requires running holdfastbrick-pair
    on the brick."""
    pairing = state.get_pairing()
    if not pairing:
        return None
    if time.time() > pairing.get("expires_at", 0):
        state.clear_pairing()
        return None
    if not secrets.compare_digest(str(pairing.get("code", "")), code):
        if state.record_pairing_failure() >= MAX_PAIRING_FAILURES:
            state.clear_pairing()
        return None
    state.clear_pairing()  # single-use
    state.clear_pairing_failures()  # success resets the slate
    return state.issue_token(client_name)


def token_id(token: str) -> str:
    """Short, non-reversible identifier for a token, safe to list and to
    build revoke URLs from. Never contains the token itself."""
    return hashlib.sha256(token.encode()).hexdigest()[:12]


async def require_token(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> str:
    if credentials is None or not state.is_valid_token(credentials.credentials):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid token. Pair with the device first.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return credentials.credentials


# --- token management (revocation was missing entirely before this) -----------

router = APIRouter(prefix="/auth", tags=["auth"], dependencies=[Depends(require_token)])


@router.get("/tokens", response_model=list[TokenInfo])
async def list_tokens() -> list[TokenInfo]:
    """Every paired device's token, by id. Ids are short hashes; the token
    values themselves are never returned."""
    return [
        TokenInfo(
            id=token_id(raw_token),
            client_name=str(meta.get("client", "")),
            created_at=meta.get("created_at"),
        )
        for raw_token, meta in state.tokens.items()
    ]


@router.delete("/tokens/self")
async def revoke_self(token: str = Depends(require_token)) -> dict:
    """Revoke the token making this call (a lost phone revoking itself).
    Holding the token is proof enough; no extra gate."""
    state.revoke_token(token)
    return {"ok": True, "message": "This device's access is revoked."}


@router.delete("/tokens/{token_id_value}")
async def revoke_token_by_id(token_id_value: str) -> dict:
    """Revoke a paired device by its listed id.

    v1 tradeoff: any paired device may revoke any other. The mitigation is
    the pairing flow itself — minting a new token requires someone at the
    brick running holdfastbrick-pair — so a stolen token cannot bring in
    company, and a stolen phone can be cut off by any remaining device."""
    for raw_token in list(state.tokens):
        if token_id(raw_token) == token_id_value:
            state.revoke_token(raw_token)
            return {"ok": True, "message": "Token revoked."}
    raise HTTPException(status_code=404, detail="No paired device has that id.")
