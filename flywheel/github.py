"""GitHub API helpers for the flywheel system."""

from __future__ import annotations

import os
import time
from datetime import datetime, timedelta
from typing import Any, Optional

import structlog

logger = structlog.get_logger("flywheel.github")

# Default GitHub API base
GITHUB_API_BASE = "https://api.github.com"


def get_github_client() -> Any:
    """Get an authenticated PyGitHub client."""
    try:
        from github import Github
    except ImportError:
        logger.error("PyGithub not installed. Run: pip install PyGithub")
        raise

    # Try token from environment
    token = os.getenv("GITHUB_TOKEN", "")
    if not token:
        # Try GitHub CLI
        try:
            import subprocess

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
        raise RuntimeError("GITHUB_TOKEN not set and gh auth not available")

    return Github(token)


def get_repo() -> Any:
    """Get the Shrike GitHub repository."""
    client = get_github_client()
    return client.get_repo("overlabbed-com/shrike")


def create_issue(
    title: str,
    body: str,
    labels: list[str],
    check_duplicate: bool = True,
) -> Optional[Any]:
    """Create a GitHub issue with duplicate checking.

    Args:
        title: Issue title
        body: Issue body (markdown)
        labels: List of label names to apply
        check_duplicate: Whether to check for duplicates before creating

    Returns:
        The created issue, or None if duplicate found.
    """
    repo = get_repo()

    # Check for duplicate
    if check_duplicate:
        existing = get_recent_issues_by_title(title)
        if existing:
            logger.info("Duplicate issue found, skipping", title=title)
            return None

    try:
        issue = repo.create_issue(title=title, body=body, labels=labels)
        logger.info("Created GitHub issue", number=issue.number, title=title)
        return issue
    except Exception as e:
        logger.error("Failed to create issue", title=title, error=str(e))
        return None


def get_recent_issues(
    component: str,
    hours: int = 24,
) -> list[Any]:
    """Get issues from the last N hours for a component.

    Args:
        component: Component name to filter by
        hours: Number of hours to look back

    Returns:
        List of issue objects.
    """
    repo = get_repo()
    cutoff = datetime.utcnow() - timedelta(hours=hours)

    try:
        issues = repo.get_issues(state="all")
        recent = []

        for issue in issues:
            # Filter by creation time
            if issue.created_at < cutoff:
                continue

            # Filter by label
            for label in issue.labels:
                if label.name == component:
                    recent.append(issue)
                    break

        return recent
    except Exception as e:
        logger.warning("Failed to fetch recent issues", error=str(e))
        return []


def get_recent_issues_by_title(title: str, hours: int = 24) -> Optional[Any]:
    """Check if an issue with similar title exists.

    Args:
        title: Title to search for
        hours: Number of hours to look back

    Returns:
        The existing issue if found, None otherwise.
    """
    repo = get_repo()
    cutoff = datetime.utcnow() - timedelta(hours=hours)

    try:
        issues = repo.get_issues(state="all")

        for issue in issues:
            if issue.created_at < cutoff:
                continue

            # Check for similar title (same prefix)
            if issue.title == title or issue.title.startswith(title.split("]")[0] + "]"):
                return issue

        return None
    except Exception as e:
        logger.warning("Failed to search for duplicate", error=str(e))
        return None


def add_comment(issue_number: int, comment: str) -> Optional[Any]:
    """Add a comment to an issue.

    Args:
        issue_number: The issue number
        comment: Comment body (markdown)

    Returns:
        The created comment, or None on failure.
    """
    repo = get_repo()

    try:
        issue = repo.get_issue(issue_number)
        comment_obj = issue.create_comment(comment)
        logger.info("Added comment", issue=issue_number)
        return comment_obj
    except Exception as e:
        logger.error("Failed to add comment", issue=issue_number, error=str(e))
        return None


def close_issue(issue_number: int, comment: Optional[str] = None) -> bool:
    """Close an issue with optional comment.

    Args:
        issue_number: The issue number
        comment: Optional closing comment

    Returns:
        True on success, False on failure.
    """
    repo = get_repo()

    try:
        issue = repo.get_issue(issue_number)

        if comment:
            issue.create_comment(comment)

        issue.edit(state="closed")
        logger.info("Closed issue", number=issue_number)
        return True
    except Exception as e:
        logger.error("Failed to close issue", number=issue_number, error=str(e))
        return False