from enum import Enum as PyEnum
from datetime import datetime
from pydantic import BaseModel, ConfigDict, field_serializer
from typing import List, Literal
from .models import PendingType

class FirewallIn(BaseModel):
    name: str
    api_url: str

class FirewallOut(BaseModel):
    id: int
    uuid: str
    token: str

class ReverseProxyIn(BaseModel):
    name: str
    ip: str
    ports: List[int]
    api_url: str
    model_config = ConfigDict(from_attributes=True)
    @field_serializer("ports")
    def serialize_ports(self, v: List[int]) -> List[int]:
        return v

class ReverseProxyOut(BaseModel):
    id: int
    uuid: str
    token: str

class ServiceDiscoveryIn(BaseModel):
    name: str
    bind_reverse_proxy_id: int
    api_url: str

class ServiceDiscoveryOut(BaseModel):
    id: int
    uuid: str
    token: str

class ServiceIn(BaseModel):
    service: str
    reverse_proxy_uuid: str

class ServiceOut(BaseModel):
    id: int

class RuleIn(BaseModel):
    firewall_rule_uuid: str
    action: str
    ip: str
    service: str

class RuleOut(BaseModel):
    firewall_rule_uuid: str

class PendingRequestOut(BaseModel):
    request_id: int
    secret: str

class PendingOut(BaseModel):
    id: int
    type: PendingType
    data: str
    src_ip: str
    secret: str
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

class PendingApproveOut(BaseModel):
    id: int
    status: Literal["approved", "rejected"]
    entity_id: int | None