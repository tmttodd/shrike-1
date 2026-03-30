"""Log format detection via regex/heuristic fingerprinting.

Identifies the format family of a raw log line without any ML.
This is Stage 1 of the Shrike pipeline — runs in <1ms per log.
"""

from __future__ import annotations

import re
from enum import Enum


class LogFormat(str, Enum):
    """Detected log format families."""

    SYSLOG_RFC5424 = "syslog_rfc5424"
    SYSLOG_RFC3164 = "syslog_rfc3164"
    SYSLOG_BSD = "syslog_bsd"
    CEF = "cef"
    LEEF = "leef"
    JSON = "json"
    XML = "xml"
    CSV = "csv"
    TSV = "tsv"
    KV = "kv"
    WINDOWS_EVTX_JSON = "evtx_json"
    W3C = "w3c"
    CLF = "clf"
    CUSTOM = "custom"


_SYSLOG_RFC5424 = re.compile(r"^<\d{1,3}>\d\s")
_SYSLOG_RFC3164 = re.compile(r"^<\d{1,3}>[A-Z][a-z]{2}\s")
_SYSLOG_BSD = re.compile(
    r"^(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s"
)
_CEF = re.compile(r"CEF:\d\|")
_LEEF = re.compile(r"LEEF:\d(?:\.\d)?\|")
_CLF = re.compile(
    r'^\S+\s+\S+\s+\S+\s+\[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s'
)
_KV = re.compile(r"(?:^|\s)\w+=\S+(?:\s\w+=\S+){2,}")
_W3C_HEADER = re.compile(r"^#Fields:\s")
_ZEEK_HEADER = re.compile(r"^#separator\s")
_ISO_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}")


def detect_format(raw_log: str) -> LogFormat:
    """Detect the format of a raw log line. <1ms per call."""
    if not raw_log or len(raw_log) < 5:
        return LogFormat.CUSTOM

    s = raw_log.strip()
    c = s[0]

    if c == "{":
        if '"EventID"' in s[:200] and any(f'"{k}"' in s[:300] for k in ("Channel", "Computer", "Description")):
            return LogFormat.WINDOWS_EVTX_JSON
        return LogFormat.JSON

    if c == "[" and len(s) > 1 and s[1] == "{":
        return LogFormat.JSON

    if c == "<":
        if _SYSLOG_RFC5424.match(s):
            return LogFormat.SYSLOG_RFC5424
        if _SYSLOG_RFC3164.match(s):
            return LogFormat.SYSLOG_RFC3164
        if s.startswith("<?xml") or s.startswith("<Event"):
            return LogFormat.XML
        if re.match(r"<\d{1,3}>", s):
            return LogFormat.SYSLOG_RFC3164
        return LogFormat.XML

    if _CEF.search(s[:100]):
        return LogFormat.CEF

    if _LEEF.search(s[:100]):
        return LogFormat.LEEF

    if _W3C_HEADER.match(s):
        return LogFormat.W3C

    if _ZEEK_HEADER.match(s) or ("\t" in s[:200] and s[:500].count("\t") >= 5):
        return LogFormat.TSV

    if _SYSLOG_BSD.match(s):
        return LogFormat.SYSLOG_BSD

    if _CLF.match(s):
        return LogFormat.CLF

    if _KV.search(s[:300]):
        return LogFormat.KV

    if _ISO_TIMESTAMP.match(s):
        if "," in s and s.count(",") >= 3:
            return LogFormat.CSV
        return LogFormat.CUSTOM

    if "," in s and s[:500].count(",") >= 4:
        return LogFormat.CSV

    return LogFormat.CUSTOM
