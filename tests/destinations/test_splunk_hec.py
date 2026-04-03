"""Tests for the Splunk HEC destination."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from shrike.destinations.splunk_hec import (
    SplunkHECDestination,
    _is_retryable,
    class_uid_to_index,
)


# ------------------------------------------------------------------
# Index routing
# ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("uid", "expected"),
    [
        (1, "ocsf-iam"),
        (3, "ocsf-iam"),
        (2, "ocsf-findings"),
        (4, "ocsf-network"),
        (5, "ocsf-discovery"),
        (6, "ocsf-application"),
        (1001, "ocsf-system"),
        (1007, "ocsf-system"),
        (None, "ocsf-raw"),
        (9999, "ocsf-raw"),
    ],
)
def test_index_routing(uid: int | None, expected: str) -> None:
    assert class_uid_to_index(uid) == expected


# ------------------------------------------------------------------
# HEC event formatting
# ------------------------------------------------------------------


def test_format_hec_event(tmp_path: Path) -> None:
    dest = SplunkHECDestination(
        url="https://splunk.example.com",
        token="test-token",
        wal_dir=str(tmp_path / "wal"),
    )
    event = {"category_uid": 4, "src_ip": "10.0.0.1"}
    formatted = dest._format_hec_event(event)

    assert formatted["index"] == "ocsf-network"
    assert formatted["sourcetype"] == "_json"
    assert formatted["event"] is event


# ------------------------------------------------------------------
# send_batch success
# ------------------------------------------------------------------


async def test_send_batch_success(tmp_path: Path) -> None:
    dest = SplunkHECDestination(
        url="https://splunk.example.com",
        token="test-token",
        wal_dir=str(tmp_path / "wal"),
    )

    events = [
        {"category_uid": 1, "user": "alice"},
        {"category_uid": 2, "finding": "cve-123"},
    ]

    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_resp.__aexit__ = AsyncMock(return_value=False)

    mock_post = MagicMock(return_value=mock_resp)

    mock_session = AsyncMock()
    mock_session.post = mock_post
    mock_session.closed = False

    # Patch _get_session to return the mock session
    dest._session = mock_session

    result = await dest.send_batch(events)

    assert result.accepted == 2
    assert result.rejected == 0
    assert result.retryable == 0

    # Verify POST was called with correct URL and auth header
    call_kwargs = mock_post.call_args
    assert "Splunk test-token" in call_kwargs.kwargs["headers"]["Authorization"]
    payload = call_kwargs.kwargs["data"]
    lines = payload.strip().split("\n")
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["index"] == "ocsf-iam"


# ------------------------------------------------------------------
# send_batch with empty list
# ------------------------------------------------------------------


async def test_send_batch_empty(tmp_path: Path) -> None:
    dest = SplunkHECDestination(
        url="https://splunk.example.com",
        token="test-token",
        wal_dir=str(tmp_path / "wal"),
    )
    result = await dest.send_batch([])
    assert result.accepted == 0
    assert result.retryable == 0


# ------------------------------------------------------------------
# health status
# ------------------------------------------------------------------


async def test_health_reports_healthy(tmp_path: Path) -> None:
    dest = SplunkHECDestination(
        url="https://splunk.example.com",
        token="test-token",
        wal_dir=str(tmp_path / "wal"),
    )
    status = await dest.health()
    assert status.healthy is True
    assert status.retry_count == 0


# ------------------------------------------------------------------
# Retry logic (IMPORTANT-3)
# ------------------------------------------------------------------


def test_is_retryable_transient_codes() -> None:
    """429, 500, 502, 503 are retryable."""
    assert _is_retryable(429) is True
    assert _is_retryable(500) is True
    assert _is_retryable(502) is True
    assert _is_retryable(503) is True


def test_is_retryable_permanent_codes() -> None:
    """400, 401, 403 are NOT retryable (permanent rejection)."""
    assert _is_retryable(400) is False
    assert _is_retryable(401) is False
    assert _is_retryable(403) is False
    assert _is_retryable(404) is False
    assert _is_retryable(200) is False


async def test_send_batch_400_rejected(tmp_path: Path) -> None:
    """HTTP 400 results in rejected (not retryable) events."""
    dest = SplunkHECDestination(
        url="https://splunk.example.com",
        token="test-token",
        wal_dir=str(tmp_path / "wal"),
    )

    mock_resp = AsyncMock()
    mock_resp.status = 400
    mock_resp.text = AsyncMock(return_value="Bad request")
    mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_resp.__aexit__ = AsyncMock(return_value=False)

    mock_session = AsyncMock()
    mock_session.post = MagicMock(return_value=mock_resp)
    mock_session.closed = False
    dest._session = mock_session

    result = await dest.send_batch([{"event": "data"}])
    assert result.rejected == 1
    assert result.retryable == 0
    assert result.accepted == 0


async def test_send_batch_503_retryable(tmp_path: Path) -> None:
    """HTTP 503 results in retryable events."""
    dest = SplunkHECDestination(
        url="https://splunk.example.com",
        token="test-token",
        wal_dir=str(tmp_path / "wal"),
    )

    mock_resp = AsyncMock()
    mock_resp.status = 503
    mock_resp.text = AsyncMock(return_value="Service unavailable")
    mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_resp.__aexit__ = AsyncMock(return_value=False)

    mock_session = AsyncMock()
    mock_session.post = MagicMock(return_value=mock_resp)
    mock_session.closed = False
    dest._session = mock_session

    result = await dest.send_batch([{"event": "data"}])
    assert result.retryable == 1
    assert result.rejected == 0
    assert result.accepted == 0
