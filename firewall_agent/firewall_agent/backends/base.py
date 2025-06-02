from typing import Any, Protocol, runtime_checkable

from sqlalchemy.orm import Session

from .types import RuleInfo


# ---------------------------------------------------------------------------
# Runtime-checkable protocol so we can safely call `issubclass`/`isinstance`
# inside `firewall_agent.backends.__init__`.
# ---------------------------------------------------------------------------
@runtime_checkable
class FirewallBackend(Protocol):
    """Minimal contract every backend implementation must satisfy."""

    # ------------------ Alias management ------------------
    def create_alias(self, name: str) -> str: ...
    def delete_alias(self, alias_id: str) -> None: ...

    # ------------------ Rule management ------------------
    def list_rules(self) -> dict[str, RuleInfo]: ...
    """
    List all rules that are currently active.
    
    Returns:
        dict[str, RuleInfo]: A dictionary where each key is a rule_id and the value is a RuleInfo object.    
    """

    def rule_details(self, rule_id: str) -> RuleInfo | None: ...
    """
    Get details of a specific rule by its rule_id.
        
    Args:
        rule_id: The unique identifier of the rule.
    Returns:
        RuleInfo: A dictionary containing rule details with keys:
            - 'rule_id': The unique identifier of the rule.
            - 'action': The action taken by the rule (e.g., "pass", "reject").
            - 'src_ip': The source IP address for the rule.
            - 'service_name': The name of the service associated with the rule.
    Raises:
        KeyError: If the rule_id does not exist.
    """

    # ------------------ Webhook processing ------------------
    def webhooks_rules(
        self,
        db: Session,
        payload: dict,
    ) -> tuple[list[RuleInfo], list[str]]:
        """
        Process a webhook payload and return rule change diffs.

        Args:
            db: SQLAlchemy session for database access.
            payload: Raw HTTP body from the firewall webhook.

        Returns:
            (list[RuleInfo], list[str]): A pair of lists:
            - new_rules: List of RuleInfo objects for newly enabled rules.
            - removed_rules: List of rule IDs for removed rules.
        """
        ...