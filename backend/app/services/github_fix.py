import logging

from github import Github
from github.GithubException import GithubException

from app.config import settings

logger = logging.getLogger(__name__)


class GithubPushError(Exception):
    """Raised when pushing an accepted fix back to GitHub (branch/commit/PR) fails."""


def is_github_repo(repo: dict) -> bool:
    return repo.get("source_type") in ("github", "github-mr") and bool(repo.get("github_owner")) and bool(repo.get("github_repo_name"))


def _branch_name(scan_id: str) -> str:
    return f"codeshield-fix/{scan_id}"


def _pr_title(scan_id: str) -> str:
    return f"CodeShield AI: security fixes for scan {scan_id}"


def push_fix_and_open_pr(repo: dict, scan: dict, relative_file_path: str, patched_content: str, finding: dict) -> dict:
    """Commits an already-locally-applied fix onto a shared per-scan branch on the real GitHub
    repo, opening a pull request the first time and reusing the same branch/PR for every
    subsequent accepted fix in this scan - so one scan produces one PR, not one per finding.

    Returns {"branch": str, "pr_url": str}. Raises GithubPushError on any failure; callers should
    treat this as non-fatal to the (already-applied) local fix.
    """
    if not settings.github_token:
        raise GithubPushError("No GITHUB_TOKEN configured - cannot push fixes back to GitHub.")

    try:
        client = Github(settings.github_token)
        gh_repo = client.get_repo(f"{repo['github_owner']}/{repo['github_repo_name']}")
        base_branch = repo.get("github_default_branch") or gh_repo.default_branch
        branch = scan.get("fix_branch") or _branch_name(scan["scan_id"])

        if not scan.get("fix_branch"):
            base_sha = gh_repo.get_branch(base_branch).commit.sha
            try:
                gh_repo.create_git_ref(ref=f"refs/heads/{branch}", sha=base_sha)
            except GithubException as exc:
                if exc.status != 422:  # 422 = ref already exists, safe to reuse
                    raise

        commit_message = f"Fix: {finding.get('title', 'security finding')} ({finding.get('file', relative_file_path)})"
        try:
            existing = gh_repo.get_contents(relative_file_path, ref=branch)
            gh_repo.update_file(relative_file_path, commit_message, patched_content, existing.sha, branch=branch)
        except GithubException as exc:
            if exc.status == 404:
                gh_repo.create_file(relative_file_path, commit_message, patched_content, branch=branch)
            else:
                raise

        pr_url = scan.get("pr_url")
        if not pr_url:
            try:
                pr = gh_repo.create_pull(
                    title=_pr_title(scan["scan_id"]),
                    body="Automated security fixes accepted via CodeShield AI. Review each commit before merging.",
                    head=branch,
                    base=base_branch,
                )
                pr_url = pr.html_url
            except GithubException as exc:
                # 422 here means a PR for this branch already exists (e.g. a prior attempt
                # partially succeeded) - look it up instead of failing the whole operation.
                if exc.status == 422:
                    existing_prs = gh_repo.get_pulls(state="open", head=f"{repo['github_owner']}:{branch}")
                    pr_url = existing_prs[0].html_url if existing_prs.totalCount else None
                else:
                    raise

        logger.info("github_fix: pushed fix to %s@%s, PR=%s", repo["source"], branch, pr_url)
        return {"branch": branch, "pr_url": pr_url}
    except GithubException as exc:
        raise GithubPushError(f"GitHub API error: {exc.data.get('message', str(exc))}") from exc
