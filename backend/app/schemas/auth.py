from pydantic import BaseModel, Field

ROLES = {"super_admin", "developer", "manager"}


def normalize_role(role: str | None) -> str:
    normalized = str(role or "manager").strip().lower().replace(" ", "_").replace("-", "_")
    return normalized if normalized in ROLES else "manager"


class AccessFlags(BaseModel):
    main: bool = True
    configuration: bool = False
    admin: bool = False
    canAddRepository: bool = False
    canTriggerBuild: bool = False
    canManageUsers: bool = False


def access_for_role(role: str) -> AccessFlags:
    if role == "super_admin":
        return AccessFlags(
            main=True, configuration=True, admin=True,
            canAddRepository=True, canTriggerBuild=True, canManageUsers=True,
        )
    if role == "developer":
        return AccessFlags(main=True, canAddRepository=True, canTriggerBuild=True)
    return AccessFlags(main=True)


class UserOut(BaseModel):
    id: str
    user_id: str
    name: str
    username: str
    email: str
    role: str
    access: AccessFlags


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=6, max_length=128)
    role: str | None = None  # ignored: public self-registration is always "manager"


class LoginRequest(BaseModel):
    username: str
    password: str


class UpdateRoleRequest(BaseModel):
    user_id: str
    role: str


class AuthResponse(BaseModel):
    user: UserOut
    token: str
