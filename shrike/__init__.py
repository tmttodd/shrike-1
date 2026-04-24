"""Shrike - Normalized Data. Anywhere.

Log normalization pipeline: ingest via HTTP/fluent-bit, normalize to OCSF,
deliver to pluggable destinations with WAL-backed durability.
"""

from shrike.logging import setup_logging

setup_logging()

__version__ = "0.1.0"
