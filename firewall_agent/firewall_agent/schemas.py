"""Pydantic request / response models shared by API endpoints."""
from __future__ import annotations

from typing import List

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator


class ReverseProxyIn(BaseModel):
    uuid: str = Field(..., description="Client‑provided UUID")
    name: str
    ip: IPvAnyAddress
    ports: List[int] = Field(..., min_length=1)
    allowed_ips: List[str] = Field(..., min_length=1)

    model_config = ConfigDict(from_attributes=True)

    @field_validator("ports")
    @classmethod
    def _port_range(cls, v: List[int]) -> List[int]:
        for p in v:
            if not 1 <= p <= 65535:
                raise ValueError("Port must be between 1‑65535")
        return v


class ReverseProxyOut(BaseModel):
    id: str


class AliasIn(BaseModel):
    service_name: str


class AliasOut(BaseModel):
    id: str
    service_name: str

    model_config = ConfigDict(from_attributes=True)


class RuleOut(BaseModel):
    id: int
    action: str
    src_ip: str
    service_name: str | None

    model_config = ConfigDict(from_attributes=True)