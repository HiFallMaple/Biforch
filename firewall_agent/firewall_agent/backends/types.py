from typing import Literal
from pydantic import BaseModel

Action = Literal["pass", "reject"]

class RuleInfo(BaseModel):
    firewall_rule_id: str
    action: Action
    src_ip: str
    service: str