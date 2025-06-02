from typing import Any, Dict, List, Protocol, runtime_checkable

# ---------------------------------------------------------------------------
# Mark the protocol as runtime-checkable so `issubclass` / `isinstance`
# can be used safely at run time inside the dynamic loader.
# ---------------------------------------------------------------------------
@runtime_checkable
class ProxyBackend(Protocol):
    """Abstract reverse-proxy backend API that every implementation must follow."""

    # ------------------ bulk sync ------------------
    def apply_rules(self, rules: Dict[str, List[str]]) -> None: ...
    def reload(self) -> None: ...

    # ------------------ incremental ops (optional) -
    def add_rule(self, service: str, line: str) -> None: ...
    def remove_rule(self, service: str, line: str) -> None: ...
