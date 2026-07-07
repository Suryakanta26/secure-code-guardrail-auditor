import logging

from fastapi import APIRouter, Depends, HTTPException, status

from app.api.deps import require_role
from app.schemas.analysis import CustomRule
from app.schemas.auth import UserOut
from app.services import admin_store, audit_log

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/admin/coding-standards", tags=["admin"])


@router.get("", response_model=list[CustomRule])
def list_standards(_: UserOut = Depends(require_role("super_admin"))) -> list[CustomRule]:
    return admin_store.list_coding_standards()


@router.post("", response_model=CustomRule)
def create_standard(rule: CustomRule, current: UserOut = Depends(require_role("super_admin"))) -> CustomRule:
    saved = admin_store.upsert_coding_standard(rule)
    audit_log.record(current.id, "create_coding_standard", saved.rule_id)
    return saved


@router.put("/{rule_id}", response_model=CustomRule)
def update_standard(
    rule_id: str, rule: CustomRule, current: UserOut = Depends(require_role("super_admin"))
) -> CustomRule:
    rule.rule_id = rule_id
    saved = admin_store.upsert_coding_standard(rule)
    audit_log.record(current.id, "update_coding_standard", saved.rule_id)
    return saved


@router.delete("/{rule_id}")
def delete_standard(rule_id: str, current: UserOut = Depends(require_role("super_admin"))) -> dict:
    if not admin_store.delete_coding_standard(rule_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Standard not found.")
    audit_log.record(current.id, "delete_coding_standard", rule_id)
    return {"deleted": rule_id}
