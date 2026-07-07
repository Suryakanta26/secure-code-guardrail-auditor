import logging

from fastapi import APIRouter, Depends, HTTPException, status

from app.api.deps import require_role
from app.core.security import create_access_token, verify_password
from app.schemas.auth import AuthResponse, LoginRequest, RegisterRequest, UpdateRoleRequest, UserOut
from app.services import audit_log, auth_store

logger = logging.getLogger(__name__)
router = APIRouter(tags=["auth"])


@router.post("/authenticate", response_model=AuthResponse)
def authenticate(payload: LoginRequest) -> AuthResponse:
    record = auth_store.find_by_username(payload.username)
    if not record or not verify_password(payload.password, record["password_hash"]):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid username or password.")

    user = auth_store.get_user_out(record["id"])
    token = create_access_token(record["id"], user.role)
    audit_log.record(actor_user_id=record["id"], action="login", target=record["username"])
    return AuthResponse(user=user, token=token)


@router.post("/user")
def register(payload: RegisterRequest) -> dict:
    # Public self-registration is always a "manager" account, regardless of what's requested.
    try:
        user = auth_store.create_user(payload.username, payload.password, role="manager")
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    audit_log.record(actor_user_id=user.id, action="register", target=payload.username)
    return {"user": user}


@router.get("/user", response_model=list[UserOut])
def list_users(_: UserOut = Depends(require_role("super_admin"))) -> list[UserOut]:
    return auth_store.list_users()


@router.patch("/user")
def patch_role(payload: UpdateRoleRequest, current: UserOut = Depends(require_role("super_admin"))) -> dict:
    try:
        user = auth_store.update_role(payload.user_id, payload.role)
    except ValueError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc

    audit_log.record(
        actor_user_id=current.id, action="update_role", target=payload.user_id, details={"role": user.role}
    )
    return {"user": user}
