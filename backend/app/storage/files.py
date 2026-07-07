import logging
from pathlib import Path

from app.schemas.analysis import CodeFile

logger = logging.getLogger(__name__)

_SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php",
    ".cs", ".c", ".cpp", ".h", ".hpp", ".yml", ".yaml", ".json", ".env",
    ".toml", ".ini", ".cfg", ".sh", ".tf", ".txt",
}
_MAX_FILE_BYTES = 200_000
_MAX_FILES = 300


def load_files_from_folder(folder: Path) -> list[CodeFile]:
    """Walk a locally-stored repo folder into the same CodeFile shape every
    downstream detector agent expects, regardless of how it was ingested."""
    files: list[CodeFile] = []
    if not folder.exists():
        return files

    for path in sorted(folder.rglob("*")):
        if len(files) >= _MAX_FILES:
            logger.info("files: reached %d file cap while scanning %s", _MAX_FILES, folder)
            break
        if not path.is_file():
            continue

        name_lower = path.name.lower()
        is_scannable = (
            path.suffix.lower() in _SCANNABLE_EXTENSIONS
            or name_lower == "dockerfile"
            or name_lower.startswith(".env")
        )
        if not is_scannable:
            continue

        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            logger.warning("files: failed to read %s", path, exc_info=True)
            continue

        files.append(CodeFile(path=path.relative_to(folder).as_posix(), content=content))

    return files
