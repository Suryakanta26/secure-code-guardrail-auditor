import logging

import jwt
from fastapi import Depends, Header, HTTPException, status

from app.core.security import decode_access_token
from app.schemas.auth import UserOut
from app.services import auth_store

logger = logging.getLogger(__name__)


def get_current_user(authorization: str | None = Header(default=None)) -> UserOut:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing or invalid Authorization header.")

    token = authorization.split(" ", 1)[1].strip()
    try:
        payload = decode_access_token(token)
    except jwt.PyJWTError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token.") from exc

    user = auth_store.get_user_out(payload.get("sub", ""))
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User no longer exists.")
    return user


def require_role(*roles: str):
    def _dependency(user: UserOut = Depends(get_current_user)) -> UserOut:
        if user.role not in roles:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient permissions.")
        return user

    return _dependency
