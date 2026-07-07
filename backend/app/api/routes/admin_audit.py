from fastapi import APIRouter, Depends

from app.api.deps import require_role
from app.schemas.auth import UserOut
from app.services import audit_log

router = APIRouter(prefix="/admin/audit-log", tags=["admin"])


@router.get("")
def list_audit_log(_: UserOut = Depends(require_role("super_admin"))) -> list[dict]:
    return audit_log.list_entries()
