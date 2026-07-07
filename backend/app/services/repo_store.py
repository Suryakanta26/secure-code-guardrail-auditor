import uuid
from datetime import datetime, timezone

from app.config import settings
from app.storage.json_store import JsonListStore

_repos: JsonListStore | None = None
_scans: JsonListStore | None = None


def _repos_store() -> JsonListStore:
    global _repos
    if _repos is None:
        _repos = JsonListStore(settings.data_path / "repos.json", id_field="id")
    return _repos


def _scans_store() -> JsonListStore:
    global _scans
    if _scans is None:
        _scans = JsonListStore(settings.data_path / "scans.json", id_field="scan_id")
    return _scans


def create_repo(
    source: str,
    source_type: str,
    repo_path: str,
    owner_user_id: str,
    github_owner: str | None = None,
    github_repo_name: str | None = None,
    github_default_branch: str | None = None,
) -> dict:
    record = {
        "id": f"repo-{uuid.uuid4().hex[:12]}",
        "source": source,
        "source_type": source_type,
        "repo_path": repo_path,
        "owner_user_id": owner_user_id,
        # only populated for source_type="github" - lets the apply-fix flow push a fix branch
        # and open a PR back on the real repo instead of only patching the local copy.
        "github_owner": github_owner,
        "github_repo_name": github_repo_name,
        "github_default_branch": github_default_branch,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    _repos_store().upsert(record)
    return record


def create_scan(repo_id: str) -> dict:
    record = {
        "scan_id": f"scan-{uuid.uuid4().hex[:12]}",
        "repo_id": repo_id,
        "status": "pending",
        "progress": [],
        "report": None,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "completed_at": None,
    }
    _scans_store().upsert(record)
    return record


def update_scan(scan_id: str, **fields) -> dict | None:
    record = _scans_store().get(scan_id)
    if record is None:
        return None
    record.update(fields)
    _scans_store().upsert(record)
    return record


def append_scan_progress(scan_id: str, agent: str, status: str) -> None:
    record = _scans_store().get(scan_id)
    if record is None:
        return
    progress = record.get("progress") or []
    progress.append({"agent": agent, "status": status, "at": datetime.now(timezone.utc).isoformat()})
    record["progress"] = progress
    _scans_store().upsert(record)


def get_scan(scan_id: str) -> dict | None:
    return _scans_store().get(scan_id)


def update_finding_fix_status(scan_id: str, finding_id: str, status: str) -> dict | None:
    scan = _scans_store().get(scan_id)
    if scan is None or not scan.get("report"):
        return None

    updated_finding = None
    for finding in scan["report"].get("findings", []):
        if finding.get("id") == finding_id:
            finding["fix_status"] = status
            updated_finding = finding
            break

    if updated_finding is None:
        return None

    _scans_store().upsert(scan)
    return updated_finding


def get_repo(repo_id: str) -> dict | None:
    return _repos_store().get(repo_id)


def list_repos() -> list[dict]:
    return _repos_store().all()


def list_scans() -> list[dict]:
    return _scans_store().all()


def latest_scan_for_repo(repo_id: str) -> dict | None:
    scans = [s for s in list_scans() if s["repo_id"] == repo_id]
    if not scans:
        return None
    return max(scans, key=lambda s: s["started_at"])
