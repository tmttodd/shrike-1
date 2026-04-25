"""Format-aware pre-parsers for structured field extraction.

Pure Python functions that extract key-value pairs from known log formats.
No LLM, no ML — just regex and string parsing. Used by Tier 2 to pre-extract
fields before asking the LLM to map them to OCSF field names.

Each pre-parser returns a PreparsedFields or None if parsing fails.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from shrike.detector.format_detector import LogFormat


@dataclass
class PreparsedFields:
    """Fields extracted by format-aware pre-parser."""
    fields: dict[str, Any]
    format_type: str
    timestamp: str | None = None
    hostname: str | None = None
    source_app: str | None = None
    message: str | None = None


# ── Syslog BSD ──────────────────────────────────────────────

_SYSLOG_BSD_RE = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<app>[\w.\-/]+?)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.+)$"
)

def preparse_syslog_bsd(raw_log: str) -> PreparsedFields | None:
    m = _SYSLOG_BSD_RE.match(raw_log)
    if not m:
        return None
    fields = _extract_kv_from_message(m.group("message"))
    fields["_app"] = m.group("app")
    if m.group("pid"):
        fields["_pid"] = m.group("pid")
    return PreparsedFields(
        fields=fields,
        format_type="syslog_bsd",
        timestamp=m.group("timestamp"),
        hostname=m.group("hostname"),
        source_app=m.group("app"),
        message=m.group("message"),
    )


# ── Syslog RFC 5424 ────────────────────────────────────────

_SYSLOG_5424_RE = re.compile(
    r"^<\d+>\d+\s+"
    r"(?P<timestamp>\S+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<app>\S+)\s+"
    r"(?P<pid>\S+)\s+"
    r"(?P<msgid>\S+)\s+"
    r"(?P<sd>(?:\[.*?\])*|-)\s*"
    r"(?P<message>.*)$"
)

def preparse_syslog_rfc5424(raw_log: str) -> PreparsedFields | None:
    m = _SYSLOG_5424_RE.match(raw_log)
    if not m:
        return None
    fields = _extract_kv_from_message(m.group("message"))
    fields["_app"] = m.group("app")
    pid = m.group("pid")
    if pid and pid != "-":
        fields["_pid"] = pid
    return PreparsedFields(
        fields=fields,
        format_type="syslog_rfc5424",
        timestamp=m.group("timestamp"),
        hostname=m.group("hostname"),
        source_app=m.group("app"),
        message=m.group("message"),
    )


# ── Syslog RFC 3164 ────────────────────────────────────────

_SYSLOG_3164_RE = re.compile(
    r"^<(?P<pri>\d+)>"
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<app>[\w.\-/]+?)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.+)$"
)

def preparse_syslog_rfc3164(raw_log: str) -> PreparsedFields | None:
    m = _SYSLOG_3164_RE.match(raw_log)
    if not m:
        return None
    fields = _extract_kv_from_message(m.group("message"))
    fields["_app"] = m.group("app")
    fields["_pri"] = m.group("pri")
    return PreparsedFields(
        fields=fields,
        format_type="syslog_rfc3164",
        timestamp=m.group("timestamp"),
        hostname=m.group("hostname"),
        source_app=m.group("app"),
        message=m.group("message"),
    )


# ── CEF ─────────────────────────────────────────────────────

_CEF_HEADER_RE = re.compile(
    r"CEF:(?P<version>\d+)\|"
    r"(?P<vendor>[^|]*)\|"
    r"(?P<product>[^|]*)\|"
    r"(?P<dev_version>[^|]*)\|"
    r"(?P<sig_id>[^|]*)\|"
    r"(?P<name>[^|]*)\|"
    r"(?P<severity>[^|]*)\|"
    r"(?P<extensions>.*)"
)

_CEF_EXT_RE = re.compile(r"(\w+)=((?:[^=](?!(?:\w+=)))*[^=\s]?)")

def preparse_cef(raw_log: str) -> PreparsedFields | None:
    # CEF may be embedded in syslog
    cef_start = raw_log.find("CEF:")
    if cef_start < 0:
        return None
    m = _CEF_HEADER_RE.match(raw_log[cef_start:])
    if not m:
        return None
    fields: dict[str, Any] = {
        "_vendor": m.group("vendor"),
        "_product": m.group("product"),
        "_sig_id": m.group("sig_id"),
        "_name": m.group("name"),
        "_severity": m.group("severity"),
    }
    # Parse extensions
    for km in _CEF_EXT_RE.finditer(m.group("extensions")):
        fields[km.group(1)] = km.group(2).strip()
    # Extract syslog header if present
    timestamp = None
    hostname = None
    if cef_start > 0:
        header = raw_log[:cef_start].strip()
        syslog_m = re.match(r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)", header)
        if syslog_m:
            timestamp = syslog_m.group(1)
            hostname = syslog_m.group(2)
    return PreparsedFields(
        fields=fields,
        format_type="cef",
        timestamp=timestamp or fields.get("rt") or fields.get("end"),
        hostname=hostname or fields.get("dvchost"),
        source_app=m.group("product"),
        message=m.group("name"),
    )


# ── LEEF ────────────────────────────────────────────────────

_LEEF_HEADER_RE = re.compile(
    r"LEEF:(?P<version>[\d.]+)\|"
    r"(?P<vendor>[^|]*)\|"
    r"(?P<product>[^|]*)\|"
    r"(?P<dev_version>[^|]*)\|"
    r"(?P<event_id>[^|]*)\|"
    r"(?P<extensions>.*)"
)

def preparse_leef(raw_log: str) -> PreparsedFields | None:
    m = _LEEF_HEADER_RE.match(raw_log)
    if not m:
        return None
    fields: dict[str, Any] = {
        "_vendor": m.group("vendor"),
        "_product": m.group("product"),
        "_event_id": m.group("event_id"),
    }
    # LEEF uses tab-separated KV in extensions
    sep = "\t" if "\t" in m.group("extensions") else " "
    for part in m.group("extensions").split(sep):
        if "=" in part:
            k, _, v = part.partition("=")
            fields[k.strip()] = v.strip()
    return PreparsedFields(
        fields=fields,
        format_type="leef",
        timestamp=fields.get("devTime"),
        source_app=m.group("product"),
    )


# ── JSON ────────────────────────────────────────────────────

def preparse_json(raw_log: str) -> PreparsedFields | None:
    try:
        data = json.loads(raw_log.strip())
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    # Flatten one level for field mapping
    fields = _flatten_dict(data)
    # Try to find common timestamp fields
    ts = None
    for k in ("timestamp", "time", "ts", "@timestamp", "TimeCreated", "EventTime", "date"):
        if k in data:
            ts = str(data[k])
            break
    hostname = data.get("Computer") or data.get("hostname") or data.get("host")
    return PreparsedFields(
        fields=fields,
        format_type="json",
        timestamp=ts,
        hostname=str(hostname) if hostname else None,
        source_app=data.get("source") or data.get("SourceName"),
    )


# ── Key=Value ───────────────────────────────────────────────

_KV_RE = re.compile(r'(\w+)=(?:"([^"]*)"|((?:[^\s,;](?!(?:\w+=)))*\S?))')

def preparse_kv(raw_log: str) -> PreparsedFields | None:
    matches = _KV_RE.findall(raw_log)
    if len(matches) < 2:
        return None
    fields = {}
    for key, quoted_val, unquoted_val in matches:
        val = quoted_val if quoted_val else unquoted_val.strip("'\"")
        fields[key] = val
    ts = fields.get("timestamp") or fields.get("time") or fields.get("date")
    return PreparsedFields(
        fields=fields,
        format_type="kv",
        timestamp=ts,
        hostname=fields.get("host") or fields.get("hostname"),
        source_app=fields.get("source") or fields.get("app"),
    )


# ── CLF (Common Log Format) ────────────────────────────────

_CLF_RE = re.compile(
    r"^(?P<src_ip>\S+)\s+"
    r"(?P<ident>\S+)\s+"
    r"(?P<user>\S+)\s+"
    r"\[(?P<timestamp>[^\]]+)\]\s+"
    r'"(?P<method>\S+)\s+(?P<url>\S+)\s+(?P<protocol>\S+)"\s+'
    r"(?P<status>\d+)\s+"
    r"(?P<size>\S+)"
)

def preparse_clf(raw_log: str) -> PreparsedFields | None:
    m = _CLF_RE.match(raw_log)
    if not m:
        return None
    fields = {k: v for k, v in m.groupdict().items() if v != "-"}
    return PreparsedFields(
        fields=fields,
        format_type="clf",
        timestamp=m.group("timestamp"),
        hostname=None,
        source_app=None,
        message=f"{m.group('method')} {m.group('url')}",
    )


# ── W3C Extended Log Format ────────────────────────────────

def preparse_w3c(raw_log: str) -> PreparsedFields | None:
    if raw_log.startswith("#"):
        return None  # Header line, not data
    # W3C is space-separated with field names from #Fields header
    # Without the header, we can't parse reliably
    return None


# ── Helpers ─────────────────────────────────────────────────

def _extract_kv_from_message(message: str) -> dict[str, Any]:
    """Extract key=value pairs from a syslog message body."""
    fields: dict[str, Any] = {}
    for m in _KV_RE.finditer(message):
        key = m.group(1)
        val = m.group(2) if m.group(2) else m.group(3)
        fields[key] = val
    # Also try to extract IPs
    ips = re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", message)
    if ips:
        if "src_ip" not in fields and "SRC" not in fields:
            fields["_ips"] = ips
    return fields


def _flatten_dict(d: dict, prefix: str = "", sep: str = ".") -> dict[str, Any]:
    """Flatten nested dict one level for field mapping."""
    items: dict[str, Any] = {}
    for k, v in d.items():
        key = f"{prefix}{sep}{k}" if prefix else k
        if isinstance(v, dict) and len(v) <= 5:
            items.update(_flatten_dict(v, key, sep))
        else:
            items[key] = v
    return items


# ── Pre-parser Router ───────────────────────────────────────

PREPARSER_MAP: dict[LogFormat, Any] = {
    LogFormat.SYSLOG_BSD: preparse_syslog_bsd,
    LogFormat.SYSLOG_RFC5424: preparse_syslog_rfc5424,
    LogFormat.SYSLOG_RFC3164: preparse_syslog_rfc3164,
    LogFormat.CEF: preparse_cef,
    LogFormat.LEEF: preparse_leef,
    LogFormat.JSON: preparse_json,
    LogFormat.WINDOWS_EVTX_JSON: preparse_json,
    LogFormat.KV: preparse_kv,
    LogFormat.CLF: preparse_clf,
}


def preparse(raw_log: str, log_format: LogFormat) -> PreparsedFields | None:
    """Route to the correct pre-parser based on detected format."""
    parser = PREPARSER_MAP.get(log_format)
    if parser is None:
        return None
    return parser(raw_log)
