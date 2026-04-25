"""CLI entry point for the flywheel system."""

from __future__ import annotations

import argparse
import os
import sys

import structlog

from flywheel.state import DEFAULT_STATE_FILE
from flywheel.tracker import FlywheelTracker, TrackerConfig

logger = structlog.get_logger("flywheel")


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Shrike Flywheel - Continuous improvement detection system",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m flywheel --interval 60 --stability-threshold 0.01
  python -m flywheel --interval 30 --state-file /data/flywheel_state.json
        """,
    )

    parser.add_argument(
        "--interval",
        type=int,
        default=60,
        help="Detection cycle interval in seconds (default: 60)",
    )
    parser.add_argument(
        "--stability-threshold",
        type=float,
        default=0.01,
        help="Error rate threshold for STABLE status (default: 0.01 = 1%%)",
    )
    parser.add_argument(
        "--health-url",
        type=str,
        default=os.getenv("SHRIKE_HEALTH_URL", "http://shrike:8080/health"),
        help="Shrike health endpoint URL",
    )
    parser.add_argument(
        "--wal-dir",
        type=str,
        default=os.getenv("SHRIKE_WAL_DIR", "/data/wal"),
        help="WAL directory path",
    )
    parser.add_argument(
        "--log-path",
        type=str,
        default=os.getenv("SHRIKE_LOG_PATH", "/var/log/shrike"),
        help="Shrike log file path",
    )
    parser.add_argument(
        "--state-file",
        type=str,
        default=os.getenv("FLYWHEEL_STATE_FILE", DEFAULT_STATE_FILE),
        help="State file path",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single detection cycle and exit",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging",
    )

    return parser.parse_args()


def main() -> None:
    """Main entry point."""
    args = parse_args()

    # Configure logging
    log_level = "DEBUG" if args.verbose else "INFO"
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    logger.info(
        "Shrike Flywheel starting",
        interval=args.interval,
        stability_threshold=args.stability_threshold,
    )

    # Build config
    config = TrackerConfig(
        interval=args.interval,
        stability_threshold=args.stability_threshold,
        health_url=args.health_url,
        wal_dir=args.wal_dir,
        log_path=args.log_path,
        state_file=args.state_file,
    )

    # Create tracker
    tracker = FlywheelTracker(config)

    if args.once:
        # Run single cycle and exit
        result = tracker.run_cycle()
        print(f"Cycle complete: {result.issues_created} issues created")
        sys.exit(0)
    else:
        # Run continuously
        tracker.run()


if __name__ == "__main__":
    main()