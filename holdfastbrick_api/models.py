"""Shared response/request models."""

from __future__ import annotations

from pydantic import BaseModel, Field


class PairRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=6, description="6-digit pairing code")
    client_name: str = Field("iOS App", max_length=64)


class PairResponse(BaseModel):
    token: str
    device_name: str


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
