import logging
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from app.api.deps import get_current_user
from app.schemas.auth import UserOut
from app.services.github_mcp import github_mcp
from app.services import repo_store, ingestion
from app.graph.pipeline import build_pipeline

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/mcp", tags=["mr-scan"])

@router.get("/github/search")
async def search_github_repos(query: str, _=Depends(get_current_user)):
    try:
        res = await github_mcp.search_repositories(query)
        return res
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/github/pulls")
async def list_github_pulls(owner: str, repo: str, _=Depends(get_current_user)):
    try:
        res = await github_mcp.list_pull_requests(owner, repo)
        return res
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/scan/mr")
async def start_mr_scan(
    owner: str, 
    repo: str, 
    pull_number: int, 
    background_tasks: BackgroundTasks, 
    current_user: UserOut = Depends(get_current_user)
):
    # Ingest the MR code locally
    repo_id = ingestion.new_repo_id()
    try:
        import asyncio
        from starlette.concurrency import run_in_threadpool
        meta = await run_in_threadpool(ingestion.ingest_github_mr, repo_id, owner, repo, pull_number)
    except Exception as exc:
        logger.exception("mr-scan: failed to pull MR codebase locally")
        raise HTTPException(status_code=502, detail=f"Failed to fetch PR codebase: {exc}") from exc

    # Create the repo record
    repo_record = repo_store.create_repo(
        source=meta["source"],
        source_type=meta["source_type"],
        repo_path=meta["repo_path"],
        owner_user_id=current_user.id,
        github_owner=meta["github_owner"],
        github_repo_name=meta["github_repo_name"],
        github_default_branch=meta["github_default_branch"],
    )
    
    # Create the scan record
    scan = repo_store.create_scan(repo_record["id"])
    scan_id = scan["scan_id"]

    async def run_scan():
        try:
            repo_store.update_scan(scan_id, status="active", progress=[])
            repo_store.append_scan_progress(scan_id, agent="Fetching PR diff...", status="completed")
            res = await github_mcp.get_pull_request_files(owner, repo, pull_number)
            
            diff_text = ""
            if hasattr(res, "content") and len(res.content) > 0:
                raw_text = res.content[0].text
                try:
                    import json
                    files_data = json.loads(raw_text)
                    diff_lines = []
                    for file_info in files_data:
                        filename = file_info.get("filename", "unknown")
                        status = file_info.get("status", "modified")
                        patch = file_info.get("patch", "")
                        if patch:
                            diff_lines.append(f"### File: {filename} ({status})")
                            diff_lines.append("```diff")
                            diff_lines.append(patch)
                            diff_lines.append("```\n")
                    diff_text = "\n".join(diff_lines)
                except Exception as parse_exc:
                    logger.warning("Failed to parse diff JSON: %s", parse_exc)
                    diff_text = raw_text
            
            repo_store.append_scan_progress(scan_id, agent="Starting MR reasoning pipeline...", status="completed")
            
            pipeline = build_pipeline()
            state = {
                "scan_id": scan_id,
                "repo_path": repo_record["repo_path"],
                "repo_id": repo_record["id"],
                "report": {},
                "findings": [],
                "errors": [],
                "summary": {},
                "is_mr_scan": True,
                "mr_diff": diff_text
            }
            
            # Use pipeline.stream to hook into progress updates natively
            from app.services.scan_runner import _NODE_LABELS
            from datetime import datetime, timezone
            
            final_state = {}
            for step in pipeline.stream(state, stream_mode="updates"):
                for node_name, delta in step.items():
                    final_state.update(delta)
                    repo_store.append_scan_progress(
                        scan_id, agent=_NODE_LABELS.get(node_name, node_name), status="completed"
                    )

            report = final_state.get("report")
            repo_store.update_scan(
                scan_id,
                status="completed",
                report=report.model_dump(mode="json") if report and hasattr(report, "model_dump") else report,
                completed_at=datetime.now(timezone.utc).isoformat(),
            )
            
        except Exception as e:
            from datetime import datetime, timezone
            logger.exception("MR scan failed for scan_id: %s", scan_id)
            repo_store.update_scan(scan_id, status="failed", completed_at=datetime.now(timezone.utc).isoformat())
            repo_store.append_scan_progress(scan_id, agent=f"Failed: {str(e)}", status="failed")

    background_tasks.add_task(run_scan)
    return {"scan_id": scan_id, "repo_id": repo_record["id"]}
