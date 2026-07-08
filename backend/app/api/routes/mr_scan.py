from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from app.api.deps import get_current_user
from app.schemas.auth import UserOut
from app.services.github_mcp import github_mcp
from app.services import repo_store
from app.graph.pipeline import build_pipeline

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
    source = f"https://github.com/{owner}/{repo}/pull/{pull_number}"
    repo_name = f"{owner}/{repo}#PR-{pull_number}"
    
    # Create the repo record
    repo_record = repo_store.create_repo(
        source=source,
        source_type="github-mr",
        repo_path=repo_name,
        owner_user_id=current_user.id,
        github_owner=owner,
        github_repo_name=repo
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
                diff_text = res.content[0].text
            
            repo_store.append_scan_progress(scan_id, agent="Starting MR reasoning pipeline...", status="completed")
            
            pipeline = build_pipeline()
            state = {
                "scan_id": scan_id,
                "repo_path": repo_name,
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
            repo_store.update_scan(scan_id, status="failed", completed_at=datetime.now(timezone.utc).isoformat())
            repo_store.append_scan_progress(scan_id, agent=f"Failed: {str(e)}", status="failed")

    background_tasks.add_task(run_scan)
    return {"scan_id": scan_id, "repo_id": repo_record["id"]}
