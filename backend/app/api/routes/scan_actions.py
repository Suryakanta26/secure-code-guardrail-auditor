import logging
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Response, status

from app.api.deps import get_current_user, require_role
from app.schemas.analysis import CodeFix
from app.schemas.auth import UserOut
from app.services import audit_log, fix_apply, github_fix, pdf_report, repo_store
from app.services.archive import zip_folder

logger = logging.getLogger(__name__)
router = APIRouter(tags=["scan-actions"])


def _get_scan_and_repo(scan_id: str) -> tuple[dict, dict]:
    scan = repo_store.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found.")

    repo = repo_store.get_repo(scan["repo_id"])
    if repo is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Repository for this scan no longer exists.")

    return scan, repo


@router.post("/scans/{scan_id}/findings/{finding_id}/apply-fix")
def apply_fix_route(
    scan_id: str, finding_id: str, current: UserOut = Depends(require_role("developer", "super_admin"))
) -> dict:
    scan, repo = _get_scan_and_repo(scan_id)
    if scan["status"] != "completed" or not scan.get("report"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Scan is not completed yet.")

    finding = next((f for f in scan["report"]["findings"] if f["id"] == finding_id), None)
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found in this scan.")
    if not finding.get("suggested_fix"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "This finding has no suggested fix to apply.")
    if finding.get("fix_status") == "applied":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "This fix has already been applied.")

    fix = CodeFix(**finding["suggested_fix"])
    try:
        fix_apply.apply_fix(Path(repo["repo_path"]), finding["file"], fix)
    except fix_apply.FixApplyError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc

    updated = repo_store.update_finding_fix_status(scan_id, finding_id, "applied")
    audit_log.record(
        current.id, "apply_fix", target=finding["file"],
        details={"scan_id": scan_id, "finding_id": finding_id, "title": finding.get("title")},
    )
    logger.info("apply-fix: %s applied fix for finding %s in scan %s", current.id, finding_id, scan_id)

    result: dict = {"finding": updated}
    if github_fix.is_github_repo(repo):
        patched_content = (Path(repo["repo_path"]) / finding["file"]).read_text(encoding="utf-8", errors="ignore")
        try:
            push_result = github_fix.push_fix_and_open_pr(repo, scan, finding["file"], patched_content, finding)
        except github_fix.GithubPushError as exc:
            logger.warning("apply-fix: local fix applied but GitHub push failed for scan %s: %s", scan_id, exc)
            result["pr_error"] = str(exc)
        else:
            scan = repo_store.update_scan(scan_id, fix_branch=push_result["branch"], pr_url=push_result["pr_url"])
            audit_log.record(
                current.id, "push_fix_to_github", target=repo["source"],
                details={"scan_id": scan_id, "branch": push_result["branch"], "pr_url": push_result["pr_url"]},
            )
            result["fix_branch"] = push_result["branch"]
            result["pr_url"] = push_result["pr_url"]

    return result


@router.get("/scans/{scan_id}/download")
def download_scan_code(
    scan_id: str, current: UserOut = Depends(require_role("developer", "super_admin"))
) -> Response:
    scan, repo = _get_scan_and_repo(scan_id)
    archive_bytes = zip_folder(Path(repo["repo_path"]))
    audit_log.record(current.id, "download_code", target=repo["source"], details={"scan_id": scan_id})

    source_label = Path(repo["source"]).stem or repo["source_type"]
    safe_source = "".join(c if c.isalnum() or c in "-_." else "_" for c in source_label) or "repo"
    filename = f"{safe_source}-{scan_id}.zip"
    return Response(
        content=archive_bytes,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/scans/{scan_id}/report.pdf")
def download_scan_report(scan_id: str, current: UserOut = Depends(get_current_user)) -> Response:
    scan, repo = _get_scan_and_repo(scan_id)
    if scan["status"] != "completed" or not scan.get("report"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Scan is not completed yet.")

    pdf_bytes = pdf_report.build_scan_report_pdf(repo, scan)
    audit_log.record(current.id, "download_report_pdf", target=repo["source"], details={"scan_id": scan_id})

    source_label = Path(repo["source"]).stem or repo["source_type"]
    safe_source = "".join(c if c.isalnum() or c in "-_." else "_" for c in source_label) or "repo"
    filename = f"{safe_source}-{scan_id}-report.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
