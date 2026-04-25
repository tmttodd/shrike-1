"""Generic GitHub client for the flywheel framework.

Handles issue creation and duplicate checking. Configured entirely
via FlywheelConfig — just set github_repo and github_token_env.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta
from typing import Any, Optional

import structlog

logger = structlog.get_logger("flywheel.detectors.github")


class GitHubClient:
    """Generic GitHub client for issue creation.

    Uses PyGithub to create issues and check for duplicates. Token is read
    from the configured environment variable.
    """

    def __init__(
        self,
        github_repo: str,
        github_token_env: str = "GITHUB_TOKEN",
    ) -> None:
        """Initialize GitHub client.

        Args:
            github_repo: Full repo name (e.g., "owner/repo")
            github_token_env: Environment variable containing the token
        """
        self._repo_name = github_repo
        self._token_env = github_token_env
        self._github: Any = None
        self._repo: Any = None

    def _get_client(self) -> Any:
        """Get authenticated PyGithub client (lazy init)."""
        if self._github is not None:
            return self._github

        try:
            from github import Github
        except ImportError:
            logger.error("PyGithub not installed. Run: pip install PyGithub")
            raise

        token = os.environ.get(self._token_env, "")
        if not token:
            # Try GitHub CLI
            import subprocess

            try:
                result = subprocess.run(
                    ["gh", "auth", "token"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result.returncode == 0:
                    token = result.stdout.strip()
            except (subprocess.SubprocessError, FileNotFoundError):
                pass

        if not token:
            raise RuntimeError(f"{self._token_env} not set and gh auth not available")

        self._github = Github(token)
        return self._github

    def _get_repo(self) -> Any:
        """Get repository object (lazy init)."""
        if self._repo is not None:
            return self._repo

        client = self._get_client()
        self._repo = client.get_repo(self._repo_name)
        return self._repo

    def create_issue(
        self,
        title: str,
        body: str,
        labels: list[str],
    ) -> Optional[Any]:
        """Create a GitHub issue.

        Args:
            title: Issue title
            body: Issue body (markdown)
            labels: List of label names to apply

        Returns:
            The created issue, or None on failure
        """
        try:
            repo = self._get_repo()
            issue = repo.create_issue(title=title, body=body, labels=labels)
            logger.info("Created GitHub issue", number=issue.number, title=title)
            return issue
        except Exception as e:
            logger.error("Failed to create issue", title=title, error=str(e))
            return None

    def get_recent_issues(
        self,
        component: str,
        hours: int = 24,
    ) -> list[Any]:
        """Get issues from the last N hours for a component.

        Args:
            component: Component name to filter by
            hours: Number of hours to look back

        Returns:
            List of issue objects
        """
        repo = self._get_repo()
        cutoff = datetime.utcnow() - timedelta(hours=hours)

        try:
            issues = repo.get_issues(state="all")
            recent = []

            for issue in issues:
                if issue.created_at < cutoff:
                    continue

                for label in issue.labels:
                    if label.name == component:
                        recent.append(issue)
                        break

            return recent
        except Exception as e:
            logger.warning("Failed to fetch recent issues", error=str(e))
            return []

    def find_duplicate(
        self,
        title_prefix: str,
        hours: int = 24,
    ) -> Optional[Any]:
        """Find an issue with similar title.

        Args:
            title_prefix: Title prefix to search for (e.g., "[health] Service")
            hours: Number of hours to look back

        Returns:
            The existing issue if found, None otherwise
        """
        repo = self._get_repo()
        cutoff = datetime.utcnow() - timedelta(hours=hours)

        try:
            issues = repo.get_issues(state="all")

            for issue in issues:
                if issue.created_at < cutoff:
                    continue

                # Check for similar title
                if issue.title == title_prefix or issue.title.startswith(title_prefix):
                    return issue

            return None
        except Exception as e:
            logger.warning("Failed to search for duplicate", error=str(e))
            return None

    def add_comment(self, issue_number: int, comment: str) -> Optional[Any]:
        """Add a comment to an issue.

        Args:
            issue_number: The issue number
            comment: Comment body (markdown)

        Returns:
            The created comment, or None on failure
        """
        try:
            repo = self._get_repo()
            issue = repo.get_issue(issue_number)
            return issue.create_comment(comment)
        except Exception as e:
            logger.error("Failed to add comment", issue=issue_number, error=str(e))
            return None

    def close_issue(self, issue_number: int, comment: Optional[str] = None) -> bool:
        """Close an issue with optional comment.

        Args:
            issue_number: The issue number
            comment: Optional closing comment

        Returns:
            True on success, False on failure
        """
        try:
            repo = self._get_repo()
            issue = repo.get_issue(issue_number)

            if comment:
                issue.create_comment(comment)

            issue.edit(state="closed")
            logger.info("Closed issue", number=issue_number)
            return True
        except Exception as e:
            logger.error("Failed to close issue", number=issue_number, error=str(e))
            return False