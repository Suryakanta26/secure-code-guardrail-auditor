from fastapi import APIRouter

from app.services import repo_store

router = APIRouter(tags=["summary"])

_VALID_STATES = {"pending", "active", "completed", "failed"}


def _normalize_state(status: str) -> str:
    return status if status in _VALID_STATES else "pending"


@router.get("/summary")
def get_summary() -> dict:
    # Public (no auth dependency): new_frontend fetches this unconditionally on mount,
    # before login completes, and the payload is aggregate counts only (no PII/source code).
    repos = repo_store.list_repos()
    scans = repo_store.list_scans()

    repo_payload = []
    critical = 0
    high = 0
    compliance_scores: list[float] = []

    for repo in repos:
        latest = repo_store.latest_scan_for_repo(repo["id"])
        state = _normalize_state(latest["status"]) if latest else "pending"
        message = "Waiting for scan status."

        if latest:
            if latest["status"] == "failed":
                message = "Scan failed. Check backend logs for details."
            elif latest.get("progress"):
                last_step = latest["progress"][-1]
                message = f"{last_step['agent']} {last_step['status']}."

            report = latest.get("report")
            if report:
                for finding in report.get("findings", []):
                    if finding["severity"] == "critical":
                        critical += 1
                    elif finding["severity"] == "high":
                        high += 1

                statuses = report.get("compliance_status", [])
                if statuses:
                    pass_count = sum(1 for s in statuses if s["status"] == "pass")
                    compliance_scores.append(100 * pass_count / len(statuses))

        repo_payload.append({**repo, "scan_status": {"state": state, "message": message}})

    compliance_avg = round(sum(compliance_scores) / len(compliance_scores)) if compliance_scores else 0

    return {
        "total_repo": len(repos),
        "total_scan": len(scans),
        "critical_findings_count": critical,
        "high_findings_count": high,
        "compliance_score_count": compliance_avg,
        "repo": repo_payload,
    }
