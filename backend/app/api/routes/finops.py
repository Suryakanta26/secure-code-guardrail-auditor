from fastapi import APIRouter, Depends

from app.api.deps import get_current_user
from app.schemas.auth import UserOut
from app.services.langsmith_finops import get_finops_summary

router = APIRouter(tags=["finops"])


@router.get("/finops")
def get_finops(_: UserOut = Depends(get_current_user)) -> dict:
    return get_finops_summary()
