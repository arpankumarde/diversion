"""Repo fetcher — clone/cache GitHub repos for static analysis."""

from __future__ import annotations

import logging
import re
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

# Dirs to skip during analysis
SKIP_DIRS = frozenset({
    "node_modules", ".git", "vendor", "dist", "build",
    "test", "tests", "docs", "__pycache__", ".venv",
})


class RepoFetcher:
    """Clone a GitHub repo (shallow) and cache it locally."""

    def __init__(self, cache_dir: Path = Path(".nazitest_cache/repos")) -> None:
        self.cache_dir = cache_dir

    def fetch(self, repo_url: str) -> Path:
        """Clone or return cached path for a GitHub repo URL.

        Accepts:
          - https://github.com/owner/repo
          - https://github.com/owner/repo.git
          - https://github.com/owner/repo/tree/main/...
          - owner/repo (shorthand)
        """
        owner, repo = self._parse_github_url(repo_url)
        dest = self.cache_dir / f"{owner}_{repo}"

        if dest.exists() and any(dest.iterdir()):
            logger.info("Repo already cached: %s", dest)
            return dest

        dest.mkdir(parents=True, exist_ok=True)
        clone_target = f"{owner}/{repo}"
        clone_url = f"https://github.com/{owner}/{repo}.git"

        # Try gh CLI first (handles auth), fall back to git
        if self._try_gh_clone(clone_target, dest):
            return dest

        if self._try_git_clone(clone_url, dest):
            return dest

        raise RuntimeError(f"Failed to clone repo: {repo_url}")

    @staticmethod
    def _parse_github_url(url: str) -> tuple[str, str]:
        """Extract (owner, repo) from various GitHub URL formats."""
        # owner/repo shorthand
        if re.match(r"^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$", url):
            parts = url.split("/")
            return parts[0], parts[1]

        # Full URL: https://github.com/owner/repo[.git][/tree/...]
        m = re.match(
            r"https?://github\.com/([a-zA-Z0-9_.-]+)/([a-zA-Z0-9_.-]+?)(?:\.git)?(?:/.*)?$",
            url,
        )
        if m:
            return m.group(1), m.group(2)

        raise ValueError(f"Cannot parse GitHub URL: {url}")

    @staticmethod
    def _try_gh_clone(clone_target: str, dest: Path) -> bool:
        """Try cloning via gh CLI (shallow)."""
        try:
            result = subprocess.run(
                ["gh", "repo", "clone", clone_target, str(dest), "--", "--depth=1"],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode == 0:
                logger.info("Cloned via gh: %s", clone_target)
                return True
            logger.warning("gh clone failed: %s", result.stderr.strip())
        except FileNotFoundError:
            logger.debug("gh CLI not found, falling back to git")
        except subprocess.TimeoutExpired:
            logger.warning("gh clone timed out after 120s")
        return False

    @staticmethod
    def _try_git_clone(url: str, dest: Path) -> bool:
        """Try cloning via git (shallow)."""
        try:
            result = subprocess.run(
                ["git", "clone", "--depth=1", url, str(dest)],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode == 0:
                logger.info("Cloned via git: %s", url)
                return True
            logger.warning("git clone failed: %s", result.stderr.strip())
        except FileNotFoundError:
            logger.error("git not found on PATH")
        except subprocess.TimeoutExpired:
            logger.warning("git clone timed out after 120s")
        return False
