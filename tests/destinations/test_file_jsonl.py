"""Tests for the File/JSONL destination."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shrike.destinations.file_jsonl import FileJSONLDestination, _category_dir


@pytest.fixture
def output_dir(tmp_path: Path) -> Path:
    return tmp_path / "output"


async def test_writes_to_correct_category_dir(output_dir: Path) -> None:
    dest = FileJSONLDestination(str(output_dir))
    events = [
        {"category_uid": 4, "activity_id": 1, "message": "DNS query"},
        {"category_uid": 4, "activity_id": 2, "message": "HTTP GET"},
    ]

    result = await dest.send_batch(events)

    assert result.accepted == 2
    assert result.rejected == 0

    network_dir = output_dir / "network_activity"
    assert network_dir.is_dir()

    jsonl_files = list(network_dir.glob("*.jsonl"))
    assert len(jsonl_files) == 1

    lines = jsonl_files[0].read_text().strip().split("\n")
    assert len(lines) == 2
    assert json.loads(lines[0])["message"] == "DNS query"
    assert json.loads(lines[1])["message"] == "HTTP GET"


async def test_unclassified_goes_to_raw(output_dir: Path) -> None:
    dest = FileJSONLDestination(str(output_dir))
    events = [
        {"message": "no category"},
        {"category_uid": 9999, "message": "unknown category"},
    ]

    result = await dest.send_batch(events)

    assert result.accepted == 2

    raw_dir = output_dir / "raw"
    assert raw_dir.is_dir()

    jsonl_files = list(raw_dir.glob("*.jsonl"))
    assert len(jsonl_files) == 1

    lines = jsonl_files[0].read_text().strip().split("\n")
    assert len(lines) == 2


async def test_category_dir_mapping() -> None:
    assert _category_dir(1) == "iam"
    assert _category_dir(2) == "findings"
    assert _category_dir(3) == "iam"
    assert _category_dir(4) == "network_activity"
    assert _category_dir(5) == "discovery"
    assert _category_dir(6) == "application_activity"
    assert _category_dir(1001) == "system_activity"
    assert _category_dir(1007) == "system_activity"
    assert _category_dir(None) == "raw"
    assert _category_dir(9999) == "raw"


async def test_empty_batch(output_dir: Path) -> None:
    dest = FileJSONLDestination(str(output_dir))
    result = await dest.send_batch([])
    assert result.accepted == 0
    assert result.rejected == 0


async def test_health_reports_wal_state(output_dir: Path) -> None:
    dest = FileJSONLDestination(str(output_dir))
    status = await dest.health()
    assert status.healthy is True
    assert status.pending == 0


async def test_multiple_categories_in_one_batch(output_dir: Path) -> None:
    dest = FileJSONLDestination(str(output_dir))
    events = [
        {"category_uid": 1, "message": "IAM event"},
        {"category_uid": 4, "message": "network event"},
        {"category_uid": 1003, "message": "system event"},
    ]

    result = await dest.send_batch(events)
    assert result.accepted == 3

    assert (output_dir / "iam").is_dir()
    assert (output_dir / "network_activity").is_dir()
    assert (output_dir / "system_activity").is_dir()
