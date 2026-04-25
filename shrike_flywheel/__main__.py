"""CLI entry point for the Shrike flywheel system."""

from __future__ import annotations

import argparse
import sys

import structlog

from shrike_flywheel.config import load_config

logger = structlog.get_logger("shrike_flywheel")


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Shrike Flywheel - Continuous improvement detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to config.yaml",
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

    # Load config
    config = load_config(args.config)

    logger.info(
        "Shrike Flywheel starting",
        project=config.project.name,
    )

    # Import here to avoid circular imports
    from shrike_flywheel.framework import ShrikeFlywheelFramework

    framework = ShrikeFlywheelFramework(config)

    if args.once:
        results = framework.run_once()
        print(f"Cycle complete: {len(results)} issues found")
        sys.exit(0)
    else:
        framework.run_until_stable()


if __name__ == "__main__":
    main()