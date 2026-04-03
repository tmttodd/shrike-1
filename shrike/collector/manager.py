"""OTel Collector subprocess manager with auto-restart."""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import time

from shrike.collector.config_gen import generate_otel_config
from shrike.config import Config

logger = logging.getLogger(__name__)

MAX_RESTARTS_PER_MINUTE = 3
BACKOFF_SECONDS = 60
STOP_TIMEOUT_SECONDS = 10


class CollectorManager:
    """Manages the OTel Collector as a subprocess.

    Writes a generated config, starts the collector binary, and monitors it
    with auto-restart (max 3 restarts per minute, then 60s pause).
    """

    def __init__(self, config: Config, config_dir: str = "/run/shrike") -> None:
        self._config = config
        self._config_dir = config_dir
        os.makedirs(self._config_dir, mode=0o700, exist_ok=True)
        self._process: asyncio.subprocess.Process | None = None
        self._monitor_task: asyncio.Task[None] | None = None
        self._restart_times: list[float] = []
        self._stopping = False

    @property
    def is_running(self) -> bool:
        """True if the collector subprocess is alive."""
        return self._process is not None and self._process.returncode is None

    def _write_config(self) -> str:
        """Generate and write the OTel config file. Returns the file path."""
        config_path = os.path.join(self._config_dir, "otel-config.yaml")
        content = generate_otel_config(self._config)
        with open(config_path, "w") as f:
            f.write(content)
        logger.info("Wrote OTel config to %s", config_path)
        return config_path

    async def _start_process(self, config_path: str) -> None:
        """Start the otelcol-contrib subprocess."""
        binary = shutil.which("otelcol-contrib")
        if binary is None:
            raise FileNotFoundError(
                "otelcol-contrib binary not found on PATH. "
                "Install the OpenTelemetry Collector Contrib distribution."
            )

        self._process = await asyncio.create_subprocess_exec(
            binary,
            "--config",
            config_path,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        logger.info("Started otelcol-contrib (PID %d)", self._process.pid)

        # Stream stderr lines asynchronously so we see errors in real-time
        asyncio.create_task(self._stream_stderr())

    async def _stream_stderr(self) -> None:
        """Stream stderr from the collector subprocess for real-time logging."""
        if self._process is None or self._process.stderr is None:
            return
        try:
            async for line in self._process.stderr:
                text = line.decode(errors="replace").rstrip()
                if text:
                    logger.info("otelcol: %s", text)
        except (asyncio.CancelledError, ValueError):
            pass

    async def _monitor(self, config_path: str) -> None:
        """Monitor the subprocess and auto-restart on failure."""
        while not self._stopping:
            if self._process is None:
                break

            # Wait for process exit; stderr is streamed by _stream_stderr task
            await self._process.wait()

            if self._stopping:
                break

            logger.warning(
                "otelcol-contrib exited with code %d", self._process.returncode or -1
            )

            # Rate-limit restarts
            now = time.monotonic()
            self._restart_times = [
                t for t in self._restart_times if now - t < 60
            ]

            if len(self._restart_times) >= MAX_RESTARTS_PER_MINUTE:
                logger.error(
                    "Hit restart limit (%d in 60s). Pausing %ds before retry.",
                    MAX_RESTARTS_PER_MINUTE,
                    BACKOFF_SECONDS,
                )
                await asyncio.sleep(BACKOFF_SECONDS)
                self._restart_times.clear()

            self._restart_times.append(time.monotonic())
            logger.info("Restarting otelcol-contrib...")
            await self._start_process(config_path)

    async def start(self) -> None:
        """Write config, start the collector, and begin monitoring."""
        self._stopping = False
        config_path = self._write_config()
        await self._start_process(config_path)
        self._monitor_task = asyncio.create_task(self._monitor(config_path))

    async def stop(self) -> None:
        """Stop the collector subprocess gracefully (10s timeout, then kill)."""
        self._stopping = True

        if self._monitor_task is not None:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
            self._monitor_task = None

        if self._process is not None and self._process.returncode is None:
            logger.info("Terminating otelcol-contrib (PID %d)...", self._process.pid)
            self._process.terminate()
            try:
                await asyncio.wait_for(
                    self._process.wait(), timeout=STOP_TIMEOUT_SECONDS
                )
            except TimeoutError:
                logger.warning("Graceful shutdown timed out, killing process.")
                self._process.kill()
                await self._process.wait()

        self._process = None
        logger.info("Collector stopped.")
