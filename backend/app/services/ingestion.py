import io
import logging
import re
import uuid
import zipfile
from pathlib import Path

from fastapi import UploadFile
from github import Github
from github.GithubException import GithubException

from app.config import settings

logger = logging.getLogger(__name__)

_REPO_URL_RE = re.compile(r"github\.com[/:]([^/]+)/([^/.]+?)(?:\.git)?/?$")
_SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php",
    ".cs", ".c", ".cpp", ".h", ".hpp", ".yml", ".yaml", ".json", ".env",
    ".toml", ".ini", ".cfg", ".sh", ".tf", ".txt",
}
_MAX_FILES = 200
_MAX_FILE_BYTES = 200_000


def _parse_slug(repo_url: str) -> str:
    match = _REPO_URL_RE.search(repo_url.strip())
    if not match:
        raise ValueError(f"Could not parse owner/repo from URL: {repo_url}")
    owner, name = match.groups()
    return f"{owner}/{name}"


def new_repo_id() -> str:
    return f"repo-{uuid.uuid4().hex[:12]}"


def repo_dir(repo_id: str) -> Path:
    path = settings.data_path / "repos" / repo_id
    path.mkdir(parents=True, exist_ok=True)
    return path


def ingest_github(repo_id: str, repo_url: str) -> dict:
    token = settings.github_token or None
    client = Github(token) if token else Github()
    repo = client.get_repo(_parse_slug(repo_url))
    ref = repo.default_branch
    tree = repo.get_git_tree(ref, recursive=True)

    dest = repo_dir(repo_id)
    written = 0
    for entry in tree.tree:
        if written >= _MAX_FILES:
            break
        if entry.type != "blob" or not any(entry.path.endswith(ext) for ext in _SCANNABLE_EXTENSIONS):
            continue
        if (entry.size or 0) > _MAX_FILE_BYTES:
            continue
        try:
            content_file = repo.get_contents(entry.path, ref=ref)
            decoded = content_file.decoded_content.decode("utf-8", errors="ignore")
        except (GithubException, UnicodeDecodeError):
            logger.warning("ingestion: skipping %s (fetch/decode failed)", entry.path, exc_info=True)
            continue

        target = dest / entry.path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(decoded, encoding="utf-8")
        written += 1

    logger.info("ingestion: wrote %d file(s) from %s to %s", written, repo.full_name, dest)
    return {
        "source": repo_url,
        "source_type": "github",
        "repo_path": str(dest),
        "files_written": written,
        "github_owner": repo.owner.login,
        "github_repo_name": repo.name,
        "github_default_branch": ref,
    }


def _is_safe_member(name: str) -> bool:
    if name.startswith("/") or name.startswith("\\"):
        return False
    if Path(name).is_absolute():
        return False
    return ".." not in Path(name).parts


def ingest_zip(repo_id: str, upload: UploadFile, raw_bytes: bytes) -> dict:
    dest = repo_dir(repo_id)
    try:
        with zipfile.ZipFile(io.BytesIO(raw_bytes)) as archive:
            safe_members = [m for m in archive.namelist() if _is_safe_member(m)]
            archive.extractall(dest, members=safe_members)
    except zipfile.BadZipFile as exc:
        raise ValueError("Uploaded file is not a valid zip archive.") from exc

    written = sum(1 for _ in dest.rglob("*") if _.is_file())
    logger.info("ingestion: extracted zip %s -> %d file(s) at %s", upload.filename, written, dest)
    return {
        "source": upload.filename or "upload.zip",
        "source_type": "zip",
        "repo_path": str(dest),
        "files_written": written,
    }


def ingest_single_file(repo_id: str, upload: UploadFile, raw_bytes: bytes) -> dict:
    dest = repo_dir(repo_id)
    filename = Path(upload.filename or "uploaded_file").name
    (dest / filename).write_bytes(raw_bytes)
    logger.info("ingestion: saved single file %s at %s", filename, dest)
    return {
        "source": upload.filename or filename,
        "source_type": "file",
        "repo_path": str(dest),
        "files_written": 1,
    }
