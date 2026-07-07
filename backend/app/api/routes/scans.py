from fastapi import APIRouter, Depends, HTTPException, status

from app.api.deps import get_current_user
from app.schemas.auth import UserOut
from app.services import repo_store

router = APIRouter(tags=["scans"])


@router.get("/scans/{scan_id}")
def get_scan(scan_id: str, _: UserOut = Depends(get_current_user)) -> dict:
    scan = repo_store.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found.")
    return scan
