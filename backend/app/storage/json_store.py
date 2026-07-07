import json
import logging
from pathlib import Path
from threading import Lock

logger = logging.getLogger(__name__)

_locks: dict[str, Lock] = {}
_locks_guard = Lock()


def _lock_for(path: Path) -> Lock:
    key = str(path.resolve())
    with _locks_guard:
        if key not in _locks:
            _locks[key] = Lock()
        return _locks[key]


class JsonListStore:
    """Thread-safe CRUD over a JSON file containing a list of dict records.

    Single-process assumption (in-memory Lock, no file locking across processes) -
    acceptable for this app's scope (one uvicorn worker).
    """

    def __init__(self, path: Path, id_field: str = "id"):
        self.path = path
        self.id_field = id_field
        self._lock = _lock_for(path)
        if not self.path.exists():
            self._write([])

    def _read(self) -> list[dict]:
        if not self.path.exists():
            return []
        try:
            return json.loads(self.path.read_text(encoding="utf-8") or "[]")
        except json.JSONDecodeError:
            logger.warning("json_store: %s is corrupt, resetting to empty list", self.path)
            return []

    def _write(self, records: list[dict]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(records, indent=2, default=str), encoding="utf-8")

    def all(self) -> list[dict]:
        with self._lock:
            return self._read()

    def get(self, record_id: str) -> dict | None:
        with self._lock:
            return next((r for r in self._read() if r.get(self.id_field) == record_id), None)

    def upsert(self, record: dict) -> dict:
        with self._lock:
            records = self._read()
            record_id = record.get(self.id_field)
            index = next((i for i, r in enumerate(records) if r.get(self.id_field) == record_id), None)
            if index is None:
                records.append(record)
            else:
                records[index] = record
            self._write(records)
            return record

    def delete(self, record_id: str) -> bool:
        with self._lock:
            records = self._read()
            filtered = [r for r in records if r.get(self.id_field) != record_id]
            if len(filtered) == len(records):
                return False
            self._write(filtered)
            return True

    def seed_if_empty(self, records: list[dict]) -> None:
        with self._lock:
            if not self._read():
                self._write(records)
