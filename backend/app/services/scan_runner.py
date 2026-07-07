import logging
from datetime import datetime, timezone

from app.graph.pipeline import pipeline
from app.services import repo_store

logger = logging.getLogger(__name__)

_NODE_LABELS = {
    "ingest": "Repository Intake",
    "configuration": "Configuration Analysis",
    "static_scan": "Static Analysis",
    "dependency_scan": "Dependency Analysis",
    "compliance_scan": "Compliance Check",
    "risk_correlation": "Risk Correlation",
    "security_reasoning": "AI Reasoning",
    "merge": "Merging Results",
    "compliance_scoring": "Compliance Scoring",
    "report_generation": "Report Generation",
}


def run_scan(repo_id: str, scan_id: str, repo_path: str) -> None:
    """Runs the full agent pipeline for a scan, streaming per-agent progress into scans.json.

    Called via FastAPI BackgroundTasks (sync function -> runs in a threadpool,
    doesn't block the event loop).
    """
    repo_store.update_scan(scan_id, status="active", progress=[])
    initial_state = {"repo_id": repo_id, "scan_id": scan_id, "repo_path": repo_path}

    try:
        final_state: dict = {}
        for step in pipeline.stream(initial_state, stream_mode="updates"):
            for node_name, delta in step.items():
                final_state.update(delta)
                repo_store.append_scan_progress(
                    scan_id, agent=_NODE_LABELS.get(node_name, node_name), status="completed"
                )
                logger.info("scan %s: %s completed", scan_id, node_name)

        report = final_state.get("report")
        repo_store.update_scan(
            scan_id,
            status="completed",
            report=report.model_dump(mode="json") if report else None,
            completed_at=datetime.now(timezone.utc).isoformat(),
        )
        logger.info("scan %s: completed", scan_id)
    except Exception:
        logger.exception("scan %s: pipeline failed", scan_id)
        repo_store.update_scan(scan_id, status="failed", completed_at=datetime.now(timezone.utc).isoformat())
