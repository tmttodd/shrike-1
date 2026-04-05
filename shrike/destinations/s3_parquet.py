"""S3/MinIO destination — writes OCSF events to Parquet files partitioned by class."""

from __future__ import annotations

import json
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import TYPE_CHECKING

import pyarrow as pa
import pyarrow.parquet as pq

from shrike.destinations.base import Destination, HealthStatus, SendResult

if TYPE_CHECKING:
    from shrike.destinations.wal import WriteAheadLog


# OCSF class_uid → S3 prefix
_CLASS_MAP: dict[int, str] = {
    3001: "authorization",
    3002: "authentication",
    3003: "session",
    2001: "vulnerability",
    2002: "malware",
    2003: "intrusion_detection",
    2004: "threat_detection",
    2005: "security_alert",
    2006: "data_security",
    1001: "account_management",
    1002: "api_activity",
    1003: "audit_log",
    1004: "certificate_operation",
    1005: "encryption_activity",
    1006: "key_operation",
    1007: "permission_change",
    1008: "role_assignment",
    1009: "user_activity",
    4001: "connection",
    4002: "dns",
    4003: "file_transfer",
    4004: "http",
    4005: "icmp",
    4006: "network_traffic",
    4007: "port_scan",
    4008: "ssl_tls",
    5001: "device_discovery",
    5002: "network_discovery",
    5003: "service_discovery",
    6001: "application_lifecycle",
    6002: "container_activity",
    6003: "database_activity",
    6004: "process",
    7001: "configuration_change",
    7002: "storage_activity",
    7003: "system_activity",
    7004: "update_activity",
}


def _class_prefix(uid: int | None) -> str:
    """Map an OCSF class_uid to an S3 prefix.

    ``None`` or unrecognised values map to ``raw``.
    """
    if uid is None:
        return "raw"
    return _CLASS_MAP.get(uid, "raw")


class S3ParquetDestination(Destination):
    """Write OCSF events to Parquet files on S3-compatible storage.

    Events are partitioned by OCSF class_uid into separate Parquet files.
    Supports any S3-compatible backend (AWS S3, MinIO, Ceph, etc.).

    Configuration via environment variables:
        - S3_ENDPOINT_URL: Optional custom endpoint (for MinIO, etc.)
        - S3_BUCKET: Required - target bucket name
        - S3_PREFIX: Optional - prefix path within bucket
        - AWS_ACCESS_KEY_ID: Required for auth
        - AWS_SECRET_ACCESS_KEY: Required for auth
        - S3_REGION: Optional - region (default: us-east-1)
    """

    name = "s3_parquet"

    def __init__(
        self,
        bucket: str,
        prefix: str = "ocsf-events",
        wal_dir: str | None = None,
        max_size_mb: int = 500,
        endpoint_url: str | None = None,
        region: str = "us-east-1",
        **kwargs: object,
    ) -> None:
        """Initialize S3 Parquet destination.

        Args:
            bucket: S3 bucket name
            prefix: Prefix path within bucket (default: ocsf-events)
            wal_dir: Directory for write-ahead log
            max_size_mb: Max WAL size before compaction
            endpoint_url: Custom S3 endpoint (for MinIO, etc.)
            region: AWS region
        """
        self._bucket = bucket
        self._prefix = prefix.rstrip("/")
        self._region = region
        self._endpoint_url = endpoint_url

        # Import botocore lazily to avoid hard dependency
        try:
            import boto3
            from botocore.exceptions import ClientError
        except ImportError as e:
            raise ImportError(
                "S3 destination requires aioboto3. Install with: pip install aioboto3"
            ) from e

        self._s3_client = boto3.client(
            "s3",
            endpoint_url=endpoint_url,
            region_name=region,
        )

        # Verify bucket exists
        try:
            self._s_client.head_bucket(Bucket=bucket)
        except ClientError as e:
            raise RuntimeError(f"S3 bucket '{bucket}' not accessible: {e}") from e

        # WAL for durability
        wal_path = Path(wal_dir) if wal_dir else Path(f"/tmp/shrike-wal/{self.name}")
        from shrike.destinations.wal import WriteAheadLog

        self.wal: WriteAheadLog = WriteAheadLog(self.name, wal_path, max_size_mb=max_size_mb)

    async def send_batch(self, events: list[dict]) -> SendResult:
        """Upload events as Parquet files, partitioned by class_uid.

        Each class gets its own Parquet file with timestamp-based naming.
        Files are uploaded to: s3://{bucket}/{prefix}/{class_prefix}/yyyy/mm/dd/hh-mm-ss-{uuid}.parquet
        """
        if not events:
            return SendResult(accepted=0, rejected=0, retryable=0)

        # Group by class_uid
        by_class: dict[str, list[dict]] = defaultdict(list)
        for event in events:
            cls = _class_prefix(event.get("class_uid"))
            by_class[cls].append(event)

        accepted = 0
        rejected = 0
        errors: list[str] = []

        import uuid
        from datetime import datetime

        now = datetime.utcnow()
        date_prefix = now.strftime("%Y/%m/%d")

        for class_prefix, class_events in by_class.items():
            # Build Parquet file in memory
            try:
                # Flatten nested dicts for Parquet
                flattened = [_flatten_event(e) for e in class_events]

                # Create PyArrow table
                table = _dicts_to_table(flattened)

                # Write to temp file
                with tempfile.NamedTemporaryFile(suffix=".parquet", delete=False) as tmp:
                    tmp_path = tmp.name

                pq.write_table(table, tmp_path)

                # Upload to S3
                s3_key = (
                    f"{self._prefix}/{class_prefix}/{date_prefix}/"
                    f"{now.strftime('%H-%M-%S')}-{uuid.uuid4().hex[:8]}.parquet"
                )

                self._s3_client.upload_file(tmp_path, self._bucket, s3_key)

                # Cleanup temp file
                Path(tmp_path).unlink(missing_ok=True)

                accepted += len(class_events)

            except Exception as e:
                rejected += len(class_events)
                errors.append(f"{class_prefix}: {str(e)}")

        return SendResult(accepted=accepted, rejected=rejected, retryable=0, errors=errors)

    async def health(self) -> HealthStatus:
        """Check S3 bucket accessibility and WAL state."""
        try:
            self._s3_client.head_bucket(Bucket=self._bucket)
            s3_healthy = True
        except Exception:
            s3_healthy = False

        return HealthStatus(
            healthy=s3_healthy,
            pending=self.wal.pending_count,
            disk_usage_mb=self.wal.disk_usage_mb,
        )

    async def close(self) -> None:
        """Release resources."""
        self.wal.close()


def _flatten_event(event: dict, parent_key: str = "", sep: str = ".") -> dict:
    """Flatten nested dict for Parquet storage.

    Example: {"src_endpoint": {"ip": "1.2.3.4", "port": 22}}
    -> {"src_endpoint.ip": "1.2.3.4", "src_endpoint.port": 22}
    """
    items: list[tuple[str, object]] = []
    for k, v in event.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(_flatten_event(v, new_key, sep).items())
        elif isinstance(v, list):
            # Convert lists to JSON strings for Parquet
            items.append((new_key, json.dumps(v)))
        else:
            items.append((new_key, v))
    return dict(items)


def _dicts_to_table(data: list[dict]) -> pa.Table:
    """Convert list of dicts to PyArrow Table with proper schema inference."""
    if not data:
        return pa.table({})

    # Collect all unique keys
    all_keys: set[str] = set()
    for row in data:
        all_keys.update(row.keys())

    # Build column data
    columns: dict[str, list[object]] = {k: [] for k in sorted(all_keys)}
    for row in data:
        for key in columns:
            columns[key].append(row.get(key))

    # Infer types and create arrays
    arrays: dict[str, pa.Array] = {}
    for key, values in columns.items():
        # Determine column type
        non_null = [v for v in values if v is not None]

        if not non_null:
            # All nulls - use string
            arrays[key] = pa.array(values, type=pa.string())
        elif all(isinstance(v, int) for v in non_null):
            arrays[key] = pa.array(values, type=pa.int64())
        elif all(isinstance(v, float) for v in non_null):
            arrays[key] = pa.array(values, type=pa.float64())
        elif all(isinstance(v, bool) for v in non_null):
            arrays[key] = pa.array(values, type=pa.bool_())
        else:
            # Default to string
            arrays[key] = pa.array([str(v) if v is not None else None for v in values])

    return pa.table(arrays)
