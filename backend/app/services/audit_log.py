import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from app.config import settings
from app.storage.json_store import JsonListStore

logger = logging.getLogger(__name__)
_store: JsonListStore | None = None


def _get_store() -> JsonListStore:
    global _store
    if _store is None:
        _store = JsonListStore(settings.data_path / "audit_log.json", id_field="id")
    return _store


def record(actor_user_id: str, action: str, target: str = "", details: dict[str, Any] | None = None) -> None:
    entry = {
        "id": f"log-{uuid.uuid4().hex[:12]}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "actor_user_id": actor_user_id,
        "action": action,
        "target": target,
        "details": details or {},
    }
    _get_store().upsert(entry)
    logger.info("audit: %s by %s on %s", action, actor_user_id, target)


def list_entries() -> list[dict]:
    return sorted(_get_store().all(), key=lambda e: e["timestamp"], reverse=True)
