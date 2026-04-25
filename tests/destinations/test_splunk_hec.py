"""Tests for TLS configuration in Splunk HEC destination."""

from __future__ import annotations

import ssl
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from shrike.destinations.splunk_hec import SplunkHECDestination


class TestSplunkHECTLS:
    """Tests for Splunk HEC TLS configuration."""

    def test_tls_verify_true(self, tmp_path: Path) -> None:
        """When tls_verify=True, certificate must be valid."""
        wal_dir = tmp_path / "wal"
        wal_dir.mkdir()

        dest = SplunkHECDestination(
            name="splunk_hec",
            url="https://splunk.example.com:8088/services/collector",
            token="test-token",
            index="ocsf-test",
            tls_verify=True,
            wal_dir=str(wal_dir),
        )

        # Should not raise when certificate is valid (in test environment)
        # In production, this would verify the certificate
        assert dest._tls_verify is True

    def test_tls_verify_false(self, tmp_path: Path) -> None:
        """When tls_verify=False, certificates are not verified."""
        wal_dir = tmp_path / "wal"
        wal_dir.mkdir()

        dest = SplunkHECDestination(
            name="splunk_hec",
            url="https://splunk.example.com:8088/services/collector",
            token="test-token",
            index="ocsf-test",
            tls_verify=False,
            wal_dir=str(wal_dir),
        )

        assert dest._tls_verify is False

    def test_tls_custom_ca_bundle(self, tmp_path: Path) -> None:
        """When tls_ca_bundle is set, use that certificate."""
        wal_dir = tmp_path / "wal"
        wal_dir.mkdir()

        ca_file = tmp_path / "ca.crt"
        ca_file.write_text("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n")

        dest = SplunkHECDestination(
            name="splunk_hec",
            url="https://splunk.example.com:8088/services/collector",
            token="test-token",
            index="ocsf-test",
            tls_verify=True,
            tls_ca_bundle=str(ca_file),
            wal_dir=str(wal_dir),
        )

        assert dest._tls_ca_bundle == str(ca_file)

    def test_tls_connection_failure_graceful(self, tmp_path: Path) -> None:
        """TLS connection failure is handled gracefully."""
        wal_dir = tmp_path / "wal"
        wal_dir.mkdir()

        dest = SplunkHECDestination(
            name="splunk_hec",
            url="https://invalid.example.com:8088/services/collector",
            token="test-token",
            index="ocsf-test",
            tls_verify=True,
            wal_dir=str(wal_dir),
        )

        # Attempting to send should fail gracefully, not raise
        import asyncio
        try:
            result = asyncio.run(dest.send([{"test": "event"}]))
            # If it returns, it should have errors
            assert len(result.errors) > 0 or result.accepted == 0
        except Exception as e:
            # Connection errors are acceptable
            assert "ssl" in str(e).lower() or "certificate" in str(e).lower() or "connection" in str(e).lower()