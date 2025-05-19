"""Pydantic request / response models shared by the API."""
from pydantic import BaseModel, field_validator, IPvAnyNetwork


class RuleIn(BaseModel):
    action: str  # "pass" | "deny"
    ip: IPvAnyNetwork

    @field_validator("action")
    @classmethod
    def _validate_action(cls, v: str) -> str:
        if v not in {"pass", "deny"}:  # mirror Core’s contract
            raise ValueError("action must be 'pass' or 'deny'")
        return v


class RuleOut(BaseModel):
    id: int
    service_id: int
    action: str
    ip: str
