"""Shared response/request models."""

from __future__ import annotations

from pydantic import BaseModel, Field


class PairRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=6, description="6-digit pairing code")
    client_name: str = Field("iOS App", max_length=64)


class PairResponse(BaseModel):
    token: str
    device_name: str
    # sha256 of the brick's TLS certificate; phones pin this at first pair.
    # null when TLS is off (development).
    cert_fingerprint: str | None = None


class ServiceHealth(BaseModel):
    id: str
    # Friendly, layperson-facing name ("Ad Blocking"), not the daemon name.
    name: str
    running: bool
    installed: bool = True
    detail: str = ""


class OverviewResponse(BaseModel):
    device_name: str
    protected: bool
    services: list[ServiceHealth]


class ActionResponse(BaseModel):
    ok: bool
    message: str = ""


class IdentityResponse(BaseModel):
    device_name: str
    version: str
    port: int
    lan_ip: str
    tailscale_ips: list[str]
    magicdns_name: str


class TokenInfo(BaseModel):
    # Short hash of the token — never the token itself.
    id: str
    client_name: str
    # Absent on tokens issued before this field existed; the app shows "—".
    created_at: float | None = None


class ConfirmCodeResponse(BaseModel):
    # The code itself never travels over the wire: it is printed on the
    # brick's console only, so physically being at the brick is the gate.
    expires_at: str
