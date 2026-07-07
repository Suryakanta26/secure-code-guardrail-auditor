import logging

from fastapi import APIRouter, Depends, HTTPException, status

from app.api.deps import require_role
from app.schemas.analysis import CustomRule
from app.schemas.auth import UserOut
from app.services import admin_store, audit_log

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/admin/compliance-rules", tags=["admin"])


@router.get("", response_model=list[CustomRule])
def list_rules(_: UserOut = Depends(require_role("super_admin"))) -> list[CustomRule]:
    return admin_store.list_compliance_rules()


@router.post("", response_model=CustomRule)
def create_rule(rule: CustomRule, current: UserOut = Depends(require_role("super_admin"))) -> CustomRule:
    saved = admin_store.upsert_compliance_rule(rule)
    audit_log.record(current.id, "create_compliance_rule", saved.rule_id)
    return saved


@router.put("/{rule_id}", response_model=CustomRule)
def update_rule(
    rule_id: str, rule: CustomRule, current: UserOut = Depends(require_role("super_admin"))
) -> CustomRule:
    rule.rule_id = rule_id
    saved = admin_store.upsert_compliance_rule(rule)
    audit_log.record(current.id, "update_compliance_rule", saved.rule_id)
    return saved


@router.delete("/{rule_id}")
def delete_rule(rule_id: str, current: UserOut = Depends(require_role("super_admin"))) -> dict:
    if not admin_store.delete_compliance_rule(rule_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Rule not found.")
    audit_log.record(current.id, "delete_compliance_rule", rule_id)
    return {"deleted": rule_id}


@router.post("/import")
def import_rules(payload: dict, current: UserOut = Depends(require_role("super_admin"))) -> dict:
    rules = [CustomRule(**r) for r in payload.get("rules", [])]
    count = admin_store.bulk_import_compliance_rules(rules)
    audit_log.record(current.id, "bulk_import_compliance_rules", target=f"{count} rules")
    return {"imported": count}
