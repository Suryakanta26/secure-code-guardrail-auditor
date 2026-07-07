import uuid
from datetime import datetime, timezone

from app.config import settings
from app.core.security import hash_password
from app.schemas.auth import UserOut, access_for_role, normalize_role
from app.storage.json_store import JsonListStore

_store: JsonListStore | None = None

_DEFAULT_SEED_PASSWORD = "ChangeMe123!"


def _get_store() -> JsonListStore:
    global _store
    if _store is None:
        _store = JsonListStore(settings.data_path / "users.json", id_field="id")
        _seed_default_users(_store)
    return _store


def _seed_default_users(store: JsonListStore) -> None:
    now = datetime.now(timezone.utc).isoformat()
    seed = [
        {
            "id": "usr-super-admin",
            "username": "admin",
            "name": "Admin User",
            "email": "admin@secureguard.ai",
            "role": "super_admin",
            "password_hash": hash_password(_DEFAULT_SEED_PASSWORD),
            "created_at": now,
        },
        {
            "id": "usr-developer",
            "username": "developer",
            "name": "Dev User",
            "email": "developer@secureguard.ai",
            "role": "developer",
            "password_hash": hash_password(_DEFAULT_SEED_PASSWORD),
            "created_at": now,
        },
        {
            "id": "usr-manager",
            "username": "manager",
            "name": "Manager User",
            "email": "manager@secureguard.ai",
            "role": "manager",
            "password_hash": hash_password(_DEFAULT_SEED_PASSWORD),
            "created_at": now,
        },
    ]
    store.seed_if_empty(seed)


def _to_user_out(record: dict) -> UserOut:
    role = normalize_role(record["role"])
    return UserOut(
        id=record["id"],
        user_id=record["id"],
        name=record.get("name") or record["username"],
        username=record["username"],
        email=record.get("email") or f"{record['username']}@secureguard.ai",
        role=role,
        access=access_for_role(role),
    )


def find_by_username(username: str) -> dict | None:
    username_lower = username.strip().lower()
    return next((r for r in _get_store().all() if r["username"].lower() == username_lower), None)


def create_user(username: str, password: str, role: str) -> UserOut:
    if find_by_username(username):
        raise ValueError("Username already exists.")

    record = {
        "id": f"usr-{uuid.uuid4().hex[:12]}",
        "username": username.strip(),
        "name": username.strip(),
        "email": f"{username.strip()}@secureguard.ai",
        "role": normalize_role(role),
        "password_hash": hash_password(password),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    _get_store().upsert(record)
    return _to_user_out(record)


def list_users() -> list[UserOut]:
    return [_to_user_out(r) for r in _get_store().all()]


def update_role(user_id: str, role: str) -> UserOut:
    record = _get_store().get(user_id)
    if record is None:
        raise ValueError("User not found.")
    record["role"] = normalize_role(role)
    _get_store().upsert(record)
    return _to_user_out(record)


def get_user_out(user_id: str) -> UserOut | None:
    record = _get_store().get(user_id)
    return _to_user_out(record) if record else None
