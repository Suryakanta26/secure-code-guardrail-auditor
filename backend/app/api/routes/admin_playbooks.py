import logging

from fastapi import APIRouter, Depends, HTTPException, status

from app.api.deps import require_role
from app.schemas.admin import Playbook
from app.schemas.auth import UserOut
from app.services import admin_store, audit_log

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/admin/playbooks", tags=["admin"])


@router.get("", response_model=list[Playbook])
def list_playbooks(_: UserOut = Depends(require_role("super_admin"))) -> list[Playbook]:
    return admin_store.list_playbooks()


@router.post("", response_model=Playbook)
def create_playbook(playbook: Playbook, current: UserOut = Depends(require_role("super_admin"))) -> Playbook:
    saved = admin_store.upsert_playbook(playbook)
    audit_log.record(current.id, "create_playbook", saved.id)
    return saved


@router.put("/{playbook_id}", response_model=Playbook)
def update_playbook(
    playbook_id: str, playbook: Playbook, current: UserOut = Depends(require_role("super_admin"))
) -> Playbook:
    playbook.id = playbook_id
    saved = admin_store.upsert_playbook(playbook)
    audit_log.record(current.id, "update_playbook", saved.id)
    return saved


@router.delete("/{playbook_id}")
def delete_playbook(playbook_id: str, current: UserOut = Depends(require_role("super_admin"))) -> dict:
    if not admin_store.delete_playbook(playbook_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Playbook not found.")
    audit_log.record(current.id, "delete_playbook", playbook_id)
    return {"deleted": playbook_id}
