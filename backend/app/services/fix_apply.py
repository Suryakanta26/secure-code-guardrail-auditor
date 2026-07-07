import logging
from pathlib import Path

from app.schemas.analysis import CodeFix

logger = logging.getLogger(__name__)


class FixApplyError(Exception):
    """Raised when a suggested fix can no longer be safely applied."""


def apply_fix(repo_path: Path, relative_file_path: str, fix: CodeFix) -> None:
    repo_root = repo_path.resolve()
    target = (repo_root / relative_file_path).resolve()

    if repo_root != target and repo_root not in target.parents:
        raise FixApplyError("Refusing to apply a fix outside the repository folder.")
    if not target.is_file():
        raise FixApplyError(f"File {relative_file_path} no longer exists in this scan's repository.")

    # Read with universal-newline translation (default) so this matches exactly what
    # storage/files.py handed the LLM - its snippets are '\n'-only. Write back with
    # newline="\n" explicitly: Path.write_text()'s default silently re-translates '\n' to
    # '\r\n' on Windows, which would corrupt the file's line endings on every apply and
    # break exact-match matching for any subsequent fix.
    with target.open("r", encoding="utf-8", errors="ignore") as fh:
        content = fh.read()

    occurrences = content.count(fix.original_snippet)

    if occurrences == 0:
        raise FixApplyError(
            "The original code no longer matches exactly - the file may have changed since the scan "
            "(possibly from another fix already applied). Re-scan the repository to get an up-to-date fix."
        )
    if occurrences > 1:
        raise FixApplyError(
            "The original code appears more than once in this file, so the fix can't be safely targeted."
        )

    updated = content.replace(fix.original_snippet, fix.replacement_snippet, 1)
    with target.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write(updated)
    logger.info("fix_apply: applied fix to %s", target)
