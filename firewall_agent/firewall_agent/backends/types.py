from typing import Literal
from pydantic import BaseModel

Action = Literal["pass", "deny"]

class RuleInfo(BaseModel):
    firewall_rule_id: str
    action: Action
    src_ip: str
    service: str