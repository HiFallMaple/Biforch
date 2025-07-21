"""Business logic – reconcile remote firewall rules with local database and Core."""
from __future__ import annotations

from sqlalchemy.orm import Session

from ..backends import backend, RuleInfo
from ..clients.core import CoreClient, RuleIn
from ..clients.factory import get_core_client
from ..config import logging
from ..models import AliasDB, RuleDB


# def _collect_remote(db: Session) -> tuple[list[RuleInfo], list[str]]:
#     """Collect remote firewall rule diffs without modifying the database.

#     This function queries the firewall backend for all rules, then determines
#     which rules are newly enabled, which are disabled, and which existing rules
#     have changed. It does NOT write to the local database.

#     Args:
#         db (Session): SQLAlchemy database session.

#     Returns:
#         (list[dict], list[dict]): A pair of lists:
#         - new_rules: dicts with keys
#             'firewall_rule_id', 'action', 'ip', 'service'
#         - removed_rules: dicts with key 'firewall_rule_id'
#     """
#     new_rules: list[dict] = []
#     removed_rules: list[dict] = []

#     enabled_rules: dict[str, RuleInfo] = backend.list_rules()
#     # Map remote rules by id
#     enabled_ids: set[str] = set(enabled_rules.keys())
#     # Map local rules by id
#     local_rules = {r.firewall_rule_id: r for r in db.query(RuleDB).all()}
#     local_ids: set[str] = set(local_rules.keys())

#     # Added rules
#     for rule_id in enabled_ids - local_ids:
#         info = enabled_rules[rule_id]
#         new_rules.append(info)

#     # Removed rules
#     for rule_id in local_ids - enabled_ids:
#         removed_rules.append(rule_id)

#     # Modified rules: present in both but with changed attributes
#     for rule_id in enabled_ids & local_ids:
#         info: RuleInfo = enabled_rules[rule_id]
#         local = local_rules[rule_id]
#         alias = db.query(AliasDB).get(local.dest_alias_id)
#         local_service = alias.service_name if alias else None
#         if (
#             info.action != local.action or
#             info.src_ip != local.src_ip or
#             info.service != local_service
#         ):
#             # treat modification as removal then addition
#             removed_rules.append(rule_id)
#             new_rules.append(info)

#     return new_rules, removed_rules

def process_rules_change(
    db: Session,
    core: CoreClient,
    new_rules: list[RuleInfo],
    removed_rules: list[str],
) -> None:
    """Apply rule changes to the DB and notify Biforch Core.

    This function writes all new rules into the local database, deletes all
    removed rules, commits the transaction, and then calls the Core API to
    reflect these changes.

    Args:
        db (Session): SQLAlchemy database session.
        core (CoreClient): Core client instance for rule notifications.
        new_rules (list[RuleInfo]): List of new rules to add.
        removed_rules (list[str]): List of rule IDs to remove.
    """
    # 1) Update local database
    # delete first, then insert new ones
    # This ensures we don't have duplicates if the same rule is edited
    for rule in removed_rules:
        db.query(RuleDB).filter_by(
            firewall_rule_id=rule
        ).delete()

    for rule in new_rules:
        alias = db.query(AliasDB).filter_by(
            service_name=rule.service
        ).first()
        db.add(RuleDB(
            firewall_rule_id=rule.firewall_rule_id,
            action=rule.action,
            src_ip=rule.src_ip,
            dest_alias_id=alias.id,
        ))

    db.commit()
    logging.info(
        "Processed DB changes: +%d / -%d",
        len(new_rules),
        len(removed_rules),
    )

    # 2) Notify Core service
    # delete first, then insert new ones
    # This ensures we don't have duplicates if the same rule is edited
    for rule in removed_rules:
        try:
            core.delete_rule(rule)
        except Exception as exc:
            logging.warning("Core delete_rule failed: %s", exc)

    for rule in new_rules:
        try:
            core.create_rule(
                firewall_rule_id=rule.firewall_rule_id,
                action=rule.action,
                src_ip=rule.src_ip,
                service=rule.service,
            )
        except Exception as exc:
            logging.warning("Core create_rule failed: %s", exc)

def refresh_rules(db: Session, core: CoreClient, rules: list[RuleIn]) -> None:
    # 刪除所有local db 的rule
    db.query(RuleDB).delete()
    # 把rules寫入db
    for rule in rules:
        alias = db.query(AliasDB).filter_by(
            service_name=rule.service
        ).first()
        db.add(RuleDB(
            firewall_rule_id=rule.firewall_rule_id,
            action=rule.action,
            src_ip=rule.src_ip,
            dest_alias_id=alias.id,
        ))
    db.commit()
    logging.info(
        "Refreshed rules in DB: %d rules added",
        len(rules),
    )
    if not rules:
        logging.info("No rules to replace in Core, skipping")
        return
    try:
        core.replace_rules(rules)
    except Exception as exc:
        logging.error("Core replace_rules failed: %s", exc)
    
    

def sync_firewall(db: Session) -> None:
    """High-level sync: collect diffs then process changes.

    This function is the entry point for both periodic sync and webhook-driven
    sync. It fetches rule diffs via `_collect_remote` and then delegates
    to `process_rules_change`.

    Args:
        db (Session): SQLAlchemy database session.
    """
    core = get_core_client(db)

    try:
        # new_rules, removed_rules = _collect_remote(db)
        enabled_rules: dict[str, RuleInfo] = backend.list_rules()
        rules = [
            RuleIn(
                firewall_rule_id=rule.firewall_rule_id,
                action=rule.action,
                src_ip=rule.src_ip,
                service=rule.service,
            )
            for rule in enabled_rules.values()
        ]
        refresh_rules(db, core, rules)
    except Exception as exc:
        logging.error("Firewall sync failed: %s", exc)
    finally:
        db.close()
