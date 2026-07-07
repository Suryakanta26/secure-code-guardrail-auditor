import logging

from fastapi import APIRouter, Depends, HTTPException, status

from app.api.deps import require_role
from app.schemas.admin import ConfigurationRule
from app.schemas.auth import UserOut
from app.services import admin_store, audit_log

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/admin/configurations", tags=["admin"])


@router.get("", response_model=list[ConfigurationRule])
def list_configurations(_: UserOut = Depends(require_role("super_admin"))) -> list[ConfigurationRule]:
    return admin_store.list_configurations()


@router.post("", response_model=ConfigurationRule)
def create_configuration(
    rule: ConfigurationRule, current: UserOut = Depends(require_role("super_admin"))
) -> ConfigurationRule:
    saved = admin_store.upsert_configuration(rule)
    audit_log.record(current.id, "create_configuration_rule", saved.id)
    return saved


@router.put("/{rule_id}", response_model=ConfigurationRule)
def update_configuration(
    rule_id: str, rule: ConfigurationRule, current: UserOut = Depends(require_role("super_admin"))
) -> ConfigurationRule:
    rule.id = rule_id
    saved = admin_store.upsert_configuration(rule)
    audit_log.record(current.id, "update_configuration_rule", saved.id)
    return saved


@router.delete("/{rule_id}")
def delete_configuration(rule_id: str, current: UserOut = Depends(require_role("super_admin"))) -> dict:
    if not admin_store.delete_configuration(rule_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Configuration rule not found.")
    audit_log.record(current.id, "delete_configuration_rule", rule_id)
    return {"deleted": rule_id}
