import logging

from fastapi import APIRouter, Depends, HTTPException, status

from app.api.deps import require_role
from app.schemas.analysis import CustomRule
from app.schemas.auth import UserOut
from app.services import admin_store, audit_log

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/admin/owasp-rules", tags=["admin"])


@router.get("", response_model=list[CustomRule])
def list_rules(_: UserOut = Depends(require_role("super_admin"))) -> list[CustomRule]:
    return admin_store.list_owasp_rules()


@router.post("", response_model=CustomRule)
def create_rule(rule: CustomRule, current: UserOut = Depends(require_role("super_admin"))) -> CustomRule:
    saved = admin_store.upsert_owasp_rule(rule)
    audit_log.record(current.id, "create_owasp_rule", saved.rule_id)
    return saved


@router.put("/{rule_id}", response_model=CustomRule)
def update_rule(
    rule_id: str, rule: CustomRule, current: UserOut = Depends(require_role("super_admin"))
) -> CustomRule:
    rule.rule_id = rule_id
    saved = admin_store.upsert_owasp_rule(rule)
    audit_log.record(current.id, "update_owasp_rule", saved.rule_id)
    return saved


@router.delete("/{rule_id}")
def delete_rule(rule_id: str, current: UserOut = Depends(require_role("super_admin"))) -> dict:
    if not admin_store.delete_owasp_rule(rule_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Rule not found.")
    audit_log.record(current.id, "delete_owasp_rule", rule_id)
    return {"deleted": rule_id}
