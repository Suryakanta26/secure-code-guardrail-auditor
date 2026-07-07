import logging

from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, UploadFile, status

from app.api.deps import require_role
from app.schemas.auth import UserOut
from app.services import audit_log, ingestion, repo_store
from app.services.scan_runner import run_scan

logger = logging.getLogger(__name__)
router = APIRouter(tags=["ingest"])

_MAX_UPLOAD_BYTES = 25 * 1024 * 1024


@router.post("/ingest-code")
async def ingest_code(
    background_tasks: BackgroundTasks,
    github_url: str | None = Form(default=None),
    file: UploadFile | None = File(default=None),
    current: UserOut = Depends(require_role("developer", "super_admin")),
) -> dict:
    if not github_url and not file:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Provide a github_url or a file to ingest.")

    repo_id = ingestion.new_repo_id()

    try:
        if github_url:
            meta = ingestion.ingest_github(repo_id, github_url)
        else:
            raw_bytes = await file.read()
            if len(raw_bytes) > _MAX_UPLOAD_BYTES:
                raise HTTPException(status.HTTP_400_BAD_REQUEST, "Upload exceeds the 25MB limit.")
            if (file.filename or "").lower().endswith(".zip"):
                meta = ingestion.ingest_zip(repo_id, file, raw_bytes)
            else:
                meta = ingestion.ingest_single_file(repo_id, file, raw_bytes)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("ingest-code: ingestion failed")
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"Ingestion failed: {exc}") from exc

    repo = repo_store.create_repo(
        source=meta["source"], source_type=meta["source_type"], repo_path=meta["repo_path"],
        owner_user_id=current.id,
        github_owner=meta.get("github_owner"),
        github_repo_name=meta.get("github_repo_name"),
        github_default_branch=meta.get("github_default_branch"),
    )
    scan = repo_store.create_scan(repo["id"])
    audit_log.record(actor_user_id=current.id, action="ingest", target=repo["source"], details={"repo_id": repo["id"]})

    background_tasks.add_task(run_scan, repo["id"], scan["scan_id"], repo["repo_path"])

    return {
        "scan_id": scan["scan_id"],
        "repo_id": repo["id"],
        "status": "pending",
        "message": "Ingestion started",
    }
