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
"""

from __future__ import annotations

import secrets
import time

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .config import settings, state

_bearer = HTTPBearer(auto_error=False)


def open_pairing_window() -> str:
    """Open a pairing window and return the 6-digit code."""
    code = f"{secrets.randbelow(1_000_000):06d}"
    state.set_pairing(code, time.time() + settings.pairing_window_seconds)
    return code


def try_pair(code: str, client_name: str) -> str | None:
    """Exchange a valid pairing code for a bearer token, else None."""
    pairing = state.get_pairing()
    if not pairing:
        return None
    if time.time() > pairing.get("expires_at", 0):
        state.clear_pairing()
        return None
    if not secrets.compare_digest(str(pairing.get("code", "")), code):
        return None
    state.clear_pairing()  # single-use
    return state.issue_token(client_name)


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
