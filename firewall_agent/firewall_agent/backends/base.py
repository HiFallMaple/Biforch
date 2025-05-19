from typing import Any, Dict, List, Protocol


class FirewallBackend(Protocol):
    """Minimal contract every backend must fulfil."""

    # ------------------ Alias management ------------------
    def create_alias(self, name: str) -> str:
        ...

    def delete_alias(self, uuid: str) -> None:
        ...

    # ------------------ Rule management ------------------
    def list_rules(self) -> List[Dict[str, Any]]:
        ...

    def rule_details(self, uuid: str) -> Dict[str, Any]:
        ...
