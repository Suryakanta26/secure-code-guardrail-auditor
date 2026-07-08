import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import (
    admin_audit,
    admin_compliance,
    admin_configurations,
    admin_owasp,
    admin_playbooks,
    admin_standards,
    auth,
    finops,
    health,
    ingest,
    scan_actions,
    scans,
    summary,
    mr_scan,
)
from app.config import settings
from app.core.logging_config import configure_logging
from app.services import admin_store
from app.services.github_mcp import github_mcp
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize the Github MCP server singleton
    try:
        await github_mcp.initialize()
    except Exception as e:
        logger.error(f"Failed to start Github MCP server: {e}")
    yield
    await github_mcp.close()

configure_logging()
logger = logging.getLogger(__name__)

app = FastAPI(title="SecureGuard AI Backend", lifespan=lifespan)
logger.info("SecureGuard AI backend starting up (model=%s)", settings.openai_model)

admin_store.initialize()

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    # Content-Disposition isn't in the CORS "safelisted" response headers by default, so the
    # frontend's cross-origin fetch() can't read the download filename without this.
    expose_headers=["Content-Disposition"],
)

app.include_router(health.router)
app.include_router(auth.router)
app.include_router(finops.router)
app.include_router(ingest.router)
app.include_router(summary.router)
app.include_router(scans.router)
app.include_router(scan_actions.router)
app.include_router(admin_compliance.router)
app.include_router(admin_standards.router)
app.include_router(admin_owasp.router)
app.include_router(admin_playbooks.router)
app.include_router(admin_configurations.router)
app.include_router(admin_audit.router)
app.include_router(mr_scan.router)
