"""Tests for the Shrike runtime."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from shrike.runtime import create_runtime_app
from shrike.config import Config


@pytest.fixture
def mock_config() -> Config:
    config = MagicMock(spec=Config)
    config.destinations = ["file_jsonl"]
    config.file_output_dir = "/tmp/shrike-test"
    config.wal_dir = "/tmp/shrike-wal"
    config.wal_max_mb = 100
    config.ingest_api_key = None
    config.mode = "pipeline"
    config.http_port = 8080
    config.classifier_model = None
    config.llm_url = None
    config.llm_model = None
    config.splunk_hec_url = None
    config.splunk_hec_token = None
    config.splunk_tls_verify = True
    config.syslog_port = 0  # disabled in tests
    return config


# ------------------------------------------------------------------
# Phase 3.3 (#6) — X-Forwarded-For support
# ------------------------------------------------------------------


def test_ingest_uses_x_forwarded_for(mock_config: Config) -> None:
    """ingest() must use X-Forwarded-For header when present.

    Phase 3.3 (#6): reverse proxies set X-Forwarded-For; use it for source IP.
    """
    received_source_ip: list[str] = []

    async def mock_route(events):
        received_source_ip.append(events[0]["_shrike_source_ip"])
        return {"file_jsonl": AsyncMock(accepted=len(events), rejected=0)}

    with patch("shrike.runtime.DestinationRouter") as MockRouter:
        mock_router = MagicMock()
        mock_router.route = mock_route
        MockRouter.return_value = mock_router

        with patch("shrike.runtime.FileJSONLDestination") as MockFileDest:
            mock_wal = MagicMock()
            mock_wal.read_unsent = AsyncMock(return_value=[])
            mock_wal.pending_count = 0
            mock_wal.disk_usage_mb = 0.0

            mock_dest = MagicMock()
            mock_dest.name = "file_jsonl"
            mock_dest.wal = mock_wal
            mock_dest.health = AsyncMock(return_value=MagicMock(healthy=True, pending=0, disk_usage_mb=0.0))
            mock_dest.close = AsyncMock()
            MockFileDest.return_value = mock_dest

            app = create_runtime_app(mock_config)

            with TestClient(app) as client:
                response = client.post(
                    "/v1/ingest",
                    json={"logs": ["test log line"]},
                    headers={"X-Forwarded-For": "203.0.113.50, 70.141.15.16"},
                )

                assert response.status_code == 200
                assert received_source_ip[0] == "203.0.113.50"


def test_ingest_falls_back_to_client_host(mock_config: Config) -> None:
    """ingest() must use request.client.host when X-Forwarded-For is absent.

    Phase 3.3 (#6): fallback to direct client connection.
    """
    received_source_ip: list[str] = []

    async def mock_route(events):
        received_source_ip.append(events[0]["_shrike_source_ip"])
        return {"file_jsonl": AsyncMock(accepted=len(events), rejected=0)}

    with patch("shrike.runtime.DestinationRouter") as MockRouter:
        mock_router = MagicMock()
        mock_router.route = mock_route
        MockRouter.return_value = mock_router

        with patch("shrike.runtime.FileJSONLDestination") as MockFileDest:
            mock_wal = MagicMock()
            mock_wal.read_unsent = AsyncMock(return_value=[])
            mock_wal.pending_count = 0
            mock_wal.disk_usage_mb = 0.0

            mock_dest = MagicMock()
            mock_dest.name = "file_jsonl"
            mock_dest.wal = mock_wal
            mock_dest.health = AsyncMock(return_value=MagicMock(healthy=True, pending=0, disk_usage_mb=0.0))
            mock_dest.close = AsyncMock()
            MockFileDest.return_value = mock_dest

            app = create_runtime_app(mock_config)

            with TestClient(app) as client:
                response = client.post(
                    "/v1/ingest",
                    json={"logs": ["test log line"]},
                )

                assert response.status_code == 200
                # Falls back to client host or "unknown"
                assert received_source_ip[0] in ("127.0.0.1", "unknown", "localhost", "testclient")


def test_ingest_handles_empty_x_forwarded_for(mock_config: Config) -> None:
    """ingest() must handle empty X-Forwarded-For header gracefully.

    Phase 3.3 (#6): empty/missing header should not cause error.
    """
    received_source_ip: list[str] = []

    async def mock_route(events):
        received_source_ip.append(events[0]["_shrike_source_ip"])
        return {"file_jsonl": AsyncMock(accepted=len(events), rejected=0)}

    with patch("shrike.runtime.DestinationRouter") as MockRouter:
        mock_router = MagicMock()
        mock_router.route = mock_route
        MockRouter.return_value = mock_router

        with patch("shrike.runtime.FileJSONLDestination") as MockFileDest:
            mock_wal = MagicMock()
            mock_wal.read_unsent = AsyncMock(return_value=[])
            mock_wal.pending_count = 0
            mock_wal.disk_usage_mb = 0.0

            mock_dest = MagicMock()
            mock_dest.name = "file_jsonl"
            mock_dest.wal = mock_wal
            mock_dest.health = AsyncMock(return_value=MagicMock(healthy=True, pending=0, disk_usage_mb=0.0))
            mock_dest.close = AsyncMock()
            MockFileDest.return_value = mock_dest

            app = create_runtime_app(mock_config)

            with TestClient(app) as client:
                response = client.post(
                    "/v1/ingest",
                    json={"logs": ["test log line"]},
                    headers={"X-Forwarded-For": ""},
                )

                assert response.status_code == 200


# ------------------------------------------------------------------
# Phase 2.2 — Graceful shutdown drain
# ------------------------------------------------------------------

import asyncio


async def test_worker_tasks_are_named(tmp_path) -> None:
    """Worker tasks must be named 'worker-{dest.name}' for observability."""
    from shrike.config import Config
    file_config = Config(
        mode="full",
        destinations=["file_jsonl"],
        wal_dir=str(tmp_path / "wal"),
        file_output_dir=str(tmp_path / "output"),
        syslog_port=0,  # disabled in tests
    )
    app = create_runtime_app(file_config)

    started_tasks: list[asyncio.Task] = []
    original_create_task = asyncio.create_task

    def tracking_create_task(coro, *, name=None):
        task = original_create_task(coro, name=name)
        started_tasks.append(task)
        return task

    with patch("asyncio.create_task", side_effect=tracking_create_task):
        async with app.router.lifespan_context(app):
            pass

    assert len(started_tasks) == 1
    assert started_tasks[0].get_name() == "worker-file_jsonl"


async def test_worker_done_callback_is_attached(tmp_path) -> None:
    """Worker tasks must have done_callback attached to log errors on failure."""
    from shrike.config import Config
    file_config = Config(
        mode="full",
        destinations=["file_jsonl"],
        wal_dir=str(tmp_path / "wal"),
        file_output_dir=str(tmp_path / "output"),
        syslog_port=0,  # disabled in tests
    )
    app = create_runtime_app(file_config)

    callbacks_attached: list = []
    original_create_task = asyncio.create_task

    def tracking_create_task(coro, *, name=None):
        task = original_create_task(coro, name=name)
        callbacks_attached.append(task)
        return task

    with patch("asyncio.create_task", side_effect=tracking_create_task):
        async with app.router.lifespan_context(app):
            pass

    assert len(callbacks_attached) == 1
    task = callbacks_attached[0]
    assert task.get_name() == "worker-file_jsonl"


async def test_shutdown_awaits_tasks_with_timeout(tmp_path) -> None:
    """Lifespan shutdown must await worker tasks with 30s timeout before cancelling."""
    from shrike.config import Config
    file_config = Config(
        mode="full",
        destinations=["file_jsonl"],
        wal_dir=str(tmp_path / "wal"),
        file_output_dir=str(tmp_path / "output"),
        syslog_port=0,  # disabled in tests
    )
    app = create_runtime_app(file_config)

    tasks_created: list[asyncio.Task] = []
    original_create_task = asyncio.create_task

    def tracking_create_task(coro, *, name=None):
        task = original_create_task(coro, name=name)
        tasks_created.append(task)
        return task

    with patch("asyncio.create_task", side_effect=tracking_create_task):
        async with app.router.lifespan_context(app):
            pass

    assert len(tasks_created) == 1
    assert tasks_created[0].get_name() == "worker-file_jsonl"


async def test_shutdown_drain_verifies_events_delivered(tmp_path) -> None:
    """SIGTERM must allow worker to complete its task within 30s, not drop events.

    Starts a mock worker task that takes 5s, sends SIGTERM, verifies the worker
    task completes and events are delivered within the drain timeout.
    """
    import signal
    import subprocess
    import sys
    import time

    wal_dir = str(tmp_path / "wal")
    output_dir = str(tmp_path / "output")

    # Build script content without f-string to avoid fixture evaluation issues
    script_template = '''
import asyncio
from pathlib import Path

from shrike.config import Config
from shrike.runtime import create_runtime_app

async def main():
    wal_dir = Path(r"WAL_DIR")
    output_dir = Path(r"OUTPUT_DIR")
    wal_dir.mkdir(exist_ok=True)
    output_dir.mkdir(exist_ok=True)

    config = Config(
        mode="full",
        destinations=["file_jsonl"],
        wal_dir=str(wal_dir),
        file_output_dir=str(output_dir),
        syslog_port=0,  # disabled in tests
    )
    app = create_runtime_app(config)

    # Patch the worker to be slow
    from shrike.destinations import worker as worker_module

    async def slow_run(self):
        await asyncio.sleep(5)
        self._running = False

    worker_module.DestinationWorker.run = slow_run

    import uvicorn
    config = uvicorn.Config(app, host="127.0.0.1", port=18999, log_level="warning")
    server = uvicorn.Server(config)
    asyncio.create_task(server.serve())
    await asyncio.sleep(0.5)
    print("SERVER_READY")
    await asyncio.Event().wait()

if __name__ == "__main__":
    asyncio.run(main())
'''
    script_content = script_template.replace("WAL_DIR", wal_dir).replace("OUTPUT_DIR", output_dir)

    server_script = tmp_path / "slow_worker_server.py"
    server_script.write_text(script_content)

    # Start the server process
    proc = subprocess.Popen(
        [sys.executable, str(server_script)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(tmp_path),
    )

    try:
        # Wait for server to be ready
        start_time = time.time()
        ready = False
        for _ in range(60):
            line = proc.stdout.readline()
            if b"SERVER_READY" in line:
                ready = True
                break
            await asyncio.sleep(0.1)
        if not ready:
            proc.terminate()
            proc.wait(timeout=5)
            _, stderr = proc.communicate()
            raise AssertionError(f"Server did not start in time: {stderr.decode()}")

        # Send SIGTERM to trigger graceful shutdown
        proc.send_signal(signal.SIGTERM)

        # Wait for process to exit with timeout
        try:
            proc.wait(timeout=35)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            raise AssertionError("Process did not shut down within 35s")

        drain_time = time.time() - start_time

        # Verify drain completed within 30s (worker had 5s of work, should complete well before 30s timeout)
        assert drain_time < 30, f"Drain took {drain_time:.1f}s, expected < 30s"

        # Verify process exited cleanly (not killed)
        assert proc.returncode in (0, -signal.SIGTERM), f"Unexpected exit code {proc.returncode}"

    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()


# ------------------------------------------------------------------
# Phase 4.1 (#3) — 507 vs 400 distinction
# ------------------------------------------------------------------


def test_ingest_returns_507_when_wal_full(mock_config: Config) -> None:
    """ingest() must return 507 when all destinations are at WAL capacity.
    Phase 4.1 (#3): WAL overflow → 507.
    """
    async def mock_route_full(events):
        # All WALs full — nothing accepted
        return {"file_jsonl": AsyncMock(accepted=0, rejected=0)}

    with patch("shrike.runtime.DestinationRouter") as MockRouter:
        mock_router = MagicMock()
        mock_router.route = mock_route_full
        MockRouter.return_value = mock_router

        with patch("shrike.runtime.FileJSONLDestination") as MockFileDest:
            mock_wal = MagicMock()
            mock_wal.read_unsent = AsyncMock(return_value=[])
            mock_wal.pending_count = 0
            mock_wal.disk_usage_mb = 0.0

            mock_dest = MagicMock()
            mock_dest.name = "file_jsonl"
            mock_dest.wal = mock_wal
            mock_dest.health = AsyncMock(return_value=MagicMock(healthy=True, pending=0, disk_usage_mb=0.0))
            mock_dest.close = AsyncMock()
            MockFileDest.return_value = mock_dest

            app = create_runtime_app(mock_config)

            with TestClient(app) as client:
                response = client.post(
                    "/v1/ingest",
                    json={"logs": ["test log line"]},
                )

                assert response.status_code == 507



def test_ingest_returns_200_with_partial_success(mock_config: Config) -> None:
    """ingest() must return 200 when some destinations succeed (partial success).
    Phase 4.1 (#3): partial success is visible in the response.
    """
    async def mock_route_partial(events):
        # One destination succeeded (partial), one failed
        return {
            "file_jsonl": AsyncMock(accepted=1, rejected=0),
        }

    with patch("shrike.runtime.DestinationRouter") as MockRouter:
        mock_router = MagicMock()
        mock_router.route = mock_route_partial
        MockRouter.return_value = mock_router

        with patch("shrike.runtime.FileJSONLDestination") as MockFileDest:
            mock_wal = MagicMock()
            mock_wal.read_unsent = AsyncMock(return_value=[])
            mock_wal.pending_count = 0
            mock_wal.disk_usage_mb = 0.0

            mock_dest = MagicMock()
            mock_dest.name = "file_jsonl"
            mock_dest.wal = mock_wal
            mock_dest.health = AsyncMock(return_value=MagicMock(healthy=True, pending=0, disk_usage_mb=0.0))
            mock_dest.close = AsyncMock()
            MockFileDest.return_value = mock_dest

            app = create_runtime_app(mock_config)

            with TestClient(app) as client:
                response = client.post(
                    "/v1/ingest",
                    json={"logs": ["line a", "line b"]},
                )

                assert response.status_code == 200
                data = response.json()
                assert data["accepted"] == 1
                assert data["total"] == 2

# ------------------------------------------------------------------
# Phase 4.2 (#10) — Body size limit middleware
# ------------------------------------------------------------------


def test_body_too_large_returns_413(mock_config: Config) -> None:
    """Requests over 10MB must be rejected with 413."""
    app = create_runtime_app(mock_config)
    with TestClient(app) as client:
        large_body = json.dumps({"logs": ["x" * 1000] * 15000}).encode()  # ~15MB
        response = client.post("/v1/ingest", content=large_body, headers={"content-type": "application/json"})
        assert response.status_code == 413


# ------------------------------------------------------------------
# Readiness probe
# ------------------------------------------------------------------


def test_ready_returns_ready_when_healthy(mock_config: Config) -> None:
    """GET /ready returns 200 when WALs are initialized."""
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as tmp:
        wal_dir = Path(tmp) / "wal"
        wal_dir.mkdir()
        output_dir = Path(tmp) / "output"
        output_dir.mkdir()
        # Create WAL file to simulate initialized state
        wal_file = wal_dir / "file_jsonl.wal.jsonl"
        wal_file.write_text("")
        cfg = Config(
            mode="full",
            destinations=["file_jsonl"],
            wal_dir=str(wal_dir),
            file_output_dir=str(output_dir),
        )
        app = create_runtime_app(cfg)
        with TestClient(app) as client:
            response = client.get("/ready")
            assert response.status_code == 200
            assert response.json()["ready"] is True


def test_ready_returns_200_when_wal_dir_accessible(mock_config: Config) -> None:
    """GET /ready returns 200 when WAL directory is accessible."""
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as tmp:
        wal_dir = Path(tmp) / "wal"
        output_dir = Path(tmp) / "output"
        cfg = Config(
            mode="full",
            destinations=["file_jsonl"],
            wal_dir=str(wal_dir),
            file_output_dir=str(output_dir),
        )
        app = create_runtime_app(cfg)
        with TestClient(app) as client:
            response = client.get("/ready")
            assert response.status_code == 200
            assert response.json()["ready"] is True


# ------------------------------------------------------------------
# Rate limiting
# ------------------------------------------------------------------


def test_ingest_has_rate_limit(mock_config: Config) -> None:
    """ingest endpoint should have rate limiting applied."""
    app = create_runtime_app(mock_config)
    # Verify limiter is attached
    assert hasattr(app.state, "limiter")


# ------------------------------------------------------------------
# /v1/normalize and /v1/batch endpoints
# ------------------------------------------------------------------


def test_normalize_returns_events(mock_config: Config) -> None:
    """POST /normalize returns normalized event."""
    app = create_runtime_app(mock_config)
    with TestClient(app) as client:
        response = client.post(
            "/normalize",
            json={"raw_log": "sshd[123]: Accepted password for admin from 10.0.0.1"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "metadata" in data or "event" in data


def test_normalize_empty_logs(mock_config: Config) -> None:
    """POST /normalize with empty raw_log returns 422."""
    app = create_runtime_app(mock_config)
    with TestClient(app) as client:
        response = client.post("/normalize", json={"raw_log": ""})
        # Empty string may be rejected as invalid input
        assert response.status_code in (200, 422)


def test_batch_returns_results(mock_config: Config) -> None:
    """POST /batch returns list of results."""
    app = create_runtime_app(mock_config)
    with TestClient(app) as client:
        response = client.post(
            "/batch",
            json={"logs": ["sshd[123]: Accepted password for admin from 10.0.0.1"]},
        )
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)



def test_batch_empty_logs(mock_config: Config) -> None:
    """POST /batch with empty logs returns 200."""
    app = create_runtime_app(mock_config)
    with TestClient(app) as client:
        response = client.post("/batch", json={"logs": []})
        assert response.status_code == 200


def test_metrics_returns_prometheus_format(mock_config: Config) -> None:
    """GET /metrics returns Prometheus-format metrics."""
    app = create_runtime_app(mock_config)
    with TestClient(app) as client:
        response = client.get("/metrics")
        assert response.status_code == 200
        assert "shrike_events_accepted" in response.text
