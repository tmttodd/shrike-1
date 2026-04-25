"""Tier 1: YAML-driven pattern library for deterministic OCSF extraction.

Matches logs against pre-defined regex patterns and maps extracted fields
to OCSF field names. 100% accuracy by construction — no LLM involved.
Completes in <10ms per log.

Pattern files are YAML in the patterns/ directory. Each file defines one
or more extraction patterns for a specific log source.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from shrike.detector.format_detector import LogFormat
from shrike.extractor.schema_injected_extractor import ExtractionResult


@dataclass
class PatternDef:
    """A single extraction pattern loaded from YAML."""
    name: str
    source: str
    match_formats: list[str]
    regex: re.Pattern | None
    contains: str | None
    json_has: list[str] | None
    json_match: dict[str, Any] | None
    ocsf_class_uid: int
    ocsf_class_name: str
    static_fields: dict[str, Any]
    field_map: dict[str, str]  # source_field -> ocsf_dotted_path
    severity_map: dict | None
    timestamp_config: dict | None


def _set_nested(d: dict, dotted_path: str, value: Any) -> None:
    """Set a value in a nested dict using dotted path notation.

    Example: _set_nested(d, "src_endpoint.ip", "1.2.3.4")
    → d["src_endpoint"]["ip"] = "1.2.3.4"
    """
    parts = dotted_path.split(".")
    for part in parts[:-1]:
        if part not in d:
            d[part] = {}
        elif not isinstance(d[part], dict):
            d[part] = {"_value": d[part]}  # Promote scalar to dict
        d = d[part]
    d[parts[-1]] = value


def _coerce_value(value: str, ocsf_path: str = "") -> Any:
    """Coerce string values to appropriate types.

    When ocsf_path is provided, uses schema-aware coercion (IP, port, timestamp, etc.).
    Falls back to generic coercion for untyped fields.
    """
    # Strip trailing/leading quotes
    value = value.strip("'\"")

    # Schema-aware coercion when we know the target field
    if ocsf_path:
        try:
            from shrike.evaluate.coercion import OCSFCoercer
            if not hasattr(_coerce_value, '_coercer'):
                _coerce_value._coercer = OCSFCoercer()
            result = _coerce_value._coercer.coerce(ocsf_path, value)
            if result is not value:  # Coercer changed it
                return result
        except ImportError:
            pass

    # Generic coercion fallback
    if value.lower() in ("true", "yes"):
        return True
    if value.lower() in ("false", "no"):
        return False
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    return value


def _is_valid_time_value(value: Any) -> bool:
    """Check if a value is a plausible timestamp (not a small int, not an email)."""
    if value is None:
        return False
    s = str(value)
    # Reject emails
    if "@" in s:
        return False
    # Reject empty/placeholder
    if s in ("", "None", "unknown", "0", "-"):
        return False
    # Numeric: must be in epoch range (seconds or milliseconds)
    if isinstance(value, (int, float)) or s.isdigit():
        try:
            n = float(s)
            return n > 946684800 or n > 946684800000  # After year 2000
        except ValueError:
            return False
    # String: must be at least 8 chars (shortest valid: "12:00:00")
    if len(s) < 8:
        return False
    return True


class PatternExtractor:
    """Tier 1 pattern-based OCSF extractor."""

    def __init__(self, patterns_dir: Path | None = None):
        self._patterns: list[PatternDef] = []
        self._patterns_by_format: dict[str, list[PatternDef]] = {}
        if patterns_dir is None:
            patterns_dir = Path(__file__).parent.parent.parent / "patterns"
        if patterns_dir.exists():
            self._load_patterns(patterns_dir)

    def _load_patterns(self, patterns_dir: Path) -> None:
        """Load all .yaml pattern files, compile regexes, index by format."""
        # Load hand-written patterns first (higher priority), then subdirectories
        all_files = sorted(patterns_dir.glob("*.yaml"))  # Hand-written (top-level)
        for subdir in sorted(patterns_dir.iterdir()):
            if subdir.is_dir():
                all_files += sorted(subdir.glob("*.yaml"))  # Auto-generated + mined
        for f in all_files:
            try:
                with open(f) as fh:
                    data = yaml.safe_load(fh)
                if not data or "patterns" not in data:
                    continue
                source = data.get("source", f.stem)
                for pdef in data["patterns"]:
                    match = pdef.get("match", {})
                    regex_str = match.get("regex")
                    pattern = PatternDef(
                        name=pdef["name"],
                        source=source,
                        match_formats=match.get("log_format", []),
                        regex=re.compile(regex_str) if regex_str else None,
                        contains=match.get("contains"),
                        json_has=match.get("json_has"),
                        json_match=match.get("json_match"),
                        ocsf_class_uid=pdef["ocsf_class_uid"],
                        ocsf_class_name=pdef["ocsf_class_name"],
                        static_fields=pdef.get("static", {}),
                        field_map=pdef.get("field_map", {}),
                        severity_map=pdef.get("severity_map"),
                        timestamp_config=pdef.get("timestamp"),
                    )
                    # Skip overly-greedy patterns (but allow universal catch-alls)
                    if pattern.regex and len(pattern.regex.pattern) < 15 and not pattern.contains and not pattern.json_has:
                        if "catchall" not in pattern.name and "universal" not in pattern.name:
                            continue  # Too short regex = too greedy
                    # Skip contains-only patterns with common words (massive false positive risk)
                    if pattern.contains and not pattern.regex and not pattern.json_has:
                        if pattern.contains.lower() in ("system", "config", "error", "warning", "info", "debug",
                                                         "analytics", "traps", "endpoint"):
                            continue  # Too generic contains
                    # Score pattern specificity — more specific patterns get priority
                    pattern._specificity = 0
                    if pattern.json_match:
                        pattern._specificity += 3  # Most specific
                    if pattern.json_has:
                        pattern._specificity += 2
                    if pattern.contains:
                        pattern._specificity += 1
                    if pattern.regex and len(pattern.regex.pattern) > 30:
                        pattern._specificity += 1
                    # Bonus for regex with many named groups (specific extraction)
                    if pattern.regex:
                        named_groups = len(pattern.regex.groupindex)
                        if named_groups >= 5:
                            pattern._specificity += 2
                        elif named_groups >= 3:
                            pattern._specificity += 1
                    self._patterns.append(pattern)
                    # Index by format for fast pre-filtering
                    for fmt in pattern.match_formats:
                        self._patterns_by_format.setdefault(fmt, []).append(pattern)
                    if not pattern.match_formats:
                        # No format restriction — matches any format
                        self._patterns_by_format.setdefault("_any", []).append(pattern)
            except Exception:
                pass  # Skip malformed pattern files

    def try_extract(
        self,
        raw_log: str,
        log_format: LogFormat,
        class_uid: int = 0,
        class_name: str = "",
    ) -> ExtractionResult | None:
        """Try pattern extraction. Returns None if no pattern matches."""
        start = time.monotonic()

        # Get candidate patterns for this format, sorted by specificity (most specific first)
        fmt_str = log_format.value
        candidates = self._patterns_by_format.get(fmt_str, [])
        candidates = candidates + self._patterns_by_format.get("_any", [])
        candidates = sorted(candidates, key=lambda p: -getattr(p, '_specificity', 0))

        if not candidates:
            return None

        for pattern in candidates:
            # If classifier provided a class_uid, only match patterns for that class
            # (unless class_uid is 0 = unclassified)
            if class_uid > 0 and pattern.ocsf_class_uid != class_uid:
                continue

            match = self._match_pattern(pattern, raw_log, log_format)
            if match is not None:
                confidence: dict[str, str] = {}
                # Pre-parse for KV/syslog field access in field_map
                from shrike.extractor.preparsers import preparse as _preparse
                preparsed = _preparse(raw_log, log_format)
                event = self._build_event(match, pattern, raw_log, confidence,
                                         preparsed_fields=preparsed.fields if preparsed else None)

                # Supplement: if pattern extraction is thin, run remaining
                # pre-parsed fields through alias table for extra depth
                pattern_count = sum(1 for v in confidence.values()
                                    if v in ("pattern", "alias"))
                if pattern_count < 3 and preparsed and preparsed.fields:
                    self._supplement_with_aliases(
                        event, preparsed.fields, confidence)

                # Post-extraction: enrich OCSF required fields
                self._enrich_ocsf_required(
                    event, raw_log, log_format, confidence,
                    preparsed_fields=preparsed.fields if preparsed else None)

                # Scrub invalid typed values (hostnames in IP fields, etc.)
                self._scrub_invalid_types(event, confidence)

                elapsed = (time.monotonic() - start) * 1000
                return ExtractionResult(
                    event=event,
                    class_uid=pattern.ocsf_class_uid,
                    class_name=pattern.ocsf_class_name,
                    raw_log=raw_log,
                    extraction_time_ms=elapsed,
                    confidence=confidence,
                )

        # Fallback: for logs with no pattern match, try generic alias extraction
        if class_uid > 0:
            if log_format == LogFormat.JSON:
                result = self._try_json_alias_fallback(raw_log, class_uid, class_name, start)
            else:
                result = self._try_preparse_alias_fallback(
                    raw_log, log_format, class_uid, class_name, start)
            if result is not None:
                return result

        return None

    def _try_json_alias_fallback(
        self,
        raw_log: str,
        class_uid: int,
        class_name: str,
        start_time: float,
    ) -> ExtractionResult | None:
        """Fallback extractor for JSON logs: parse fields and map via alias table."""
        import json as _json
        try:
            json_data = _json.loads(raw_log)
        except (ValueError, TypeError):
            return None
        if not isinstance(json_data, dict):
            return None

        try:
            from shrike.extractor.field_mapper import FieldMapper
            if not hasattr(PatternExtractor, '_field_mapper_instance'):
                PatternExtractor._field_mapper_instance = FieldMapper()
            mapper = PatternExtractor._field_mapper_instance
        except ImportError:
            return None

        event: dict[str, Any] = {
            "class_uid": class_uid,
            "class_name": class_name,
            "activity_id": 0,
            "severity_id": 1,
            "category_uid": class_uid // 1000,
        }
        confidence: dict[str, str] = {}

        # Walk JSON and map via alias table only (deterministic, high confidence)
        stack: list[tuple[str, dict]] = [("", json_data)]
        while stack:
            prefix, obj = stack.pop()
            if not isinstance(obj, dict):
                continue
            for k, v in obj.items():
                fk = f"{prefix}.{k}" if prefix else k
                ocsf_path = mapper._aliases.get(fk) or mapper._aliases.get(k)
                if ocsf_path and v is not None and str(v) not in ("", "None", "null"):
                    _set_nested(event, ocsf_path, _coerce_value(str(v), ocsf_path))
                    confidence[ocsf_path] = "alias"
                if isinstance(v, dict):
                    stack.append((fk, v))

        # Only return if we got meaningful extraction (3+ alias fields)
        if len(confidence) < 3:
            return None

        # Post-extraction enrichment + scrub
        self._enrich_ocsf_required(event, raw_log, LogFormat.JSON, confidence)
        self._scrub_invalid_types(event, confidence)

        elapsed = (time.monotonic() - start_time) * 1000
        return ExtractionResult(
            event=event,
            class_uid=class_uid,
            class_name=class_name,
            raw_log=raw_log,
            extraction_time_ms=elapsed,
            confidence=confidence,
        )

    def _supplement_with_aliases(
        self,
        event: dict[str, Any],
        fields: dict[str, Any],
        confidence: dict[str, str],
    ) -> None:
        """Supplement a thin extraction with alias-mapped pre-parsed fields."""
        try:
            from shrike.extractor.field_mapper import FieldMapper
            if not hasattr(PatternExtractor, '_field_mapper_instance'):
                PatternExtractor._field_mapper_instance = FieldMapper()
            mapper = PatternExtractor._field_mapper_instance
        except ImportError:
            return

        # Map syslog internal fields to OCSF paths
        _internal_map = {
            "_app": "app.name",
            "_pid": "process.pid",
        }

        for k, v in fields.items():
            if k.startswith("_"):
                ocsf_path = _internal_map.get(k)
            else:
                ocsf_path = mapper._aliases.get(k)
            if not ocsf_path or v is None or str(v) in ("", "None", "null"):
                continue
            # Don't overwrite existing values
            parts = ocsf_path.split(".")
            existing = event
            found = True
            for p in parts:
                if isinstance(existing, dict) and p in existing:
                    existing = existing[p]
                else:
                    found = False
                    break
            if not found:
                _set_nested(event, ocsf_path, _coerce_value(str(v)))
                confidence[ocsf_path] = "alias"

    @staticmethod
    def _enrich_ocsf_required(
        event: dict[str, Any],
        raw_log: str,
        log_format: LogFormat,
        confidence: dict[str, str],
        preparsed_fields: dict[str, Any] | None = None,
    ) -> None:
        """Enrich extracted event with OCSF required fields.

        Three enrichments:
        1. Syslog hostname → device.hostname (from pre-parser or syslog header)
        2. Actor mirroring — populate actor.user.name from user when missing
        3. Pre-parsed timestamp → time (from syslog header)
        """
        import re as _re

        # 1. device.hostname from syslog header
        if "device" not in event or (isinstance(event.get("device"), dict)
                                      and "hostname" not in event["device"]):
            hostname = None
            # Try pre-parsed fields first
            if preparsed_fields:
                hostname = preparsed_fields.get("hostname") or preparsed_fields.get("host")
            # Fallback: extract from syslog header
            if not hostname:
                m = _re.match(
                    r"(?:\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+",
                    raw_log,
                )
                if m:
                    hostname = m.group(1)
            if hostname and hostname not in ("", "-", "localhost"):
                if "device" not in event:
                    event["device"] = {}
                if isinstance(event.get("device"), dict):
                    event["device"]["hostname"] = hostname
                    confidence["device.hostname"] = "enrichment"

        # 2. actor.user.name from user
        user_val = event.get("user")
        if user_val and isinstance(user_val, str):
            if "actor" not in event:
                event["actor"] = {"user": {"name": user_val}}
                confidence["actor.user.name"] = "enrichment"
            elif isinstance(event.get("actor"), dict):
                if "user" not in event["actor"]:
                    event["actor"]["user"] = {"name": user_val}
                    confidence["actor.user.name"] = "enrichment"
                elif isinstance(event["actor"].get("user"), dict):
                    if "name" not in event["actor"]["user"]:
                        event["actor"]["user"]["name"] = user_val
                        confidence["actor.user.name"] = "enrichment"

        # 3. time from pre-parsed timestamp (if not already set)
        if "time" not in event and preparsed_fields:
            ts = preparsed_fields.get("timestamp") or preparsed_fields.get("time")
            if ts and _is_valid_time_value(ts):
                event["time"] = ts
                confidence["time"] = "enrichment"

        # 3b. Validate existing time field — remove if it's garbage
        if "time" in event and not _is_valid_time_value(event["time"]):
            del event["time"]
            confidence.pop("time", None)

        # 4. Port next to IP — when we have IP but no port, find port nearby
        for endpoint in ("src_endpoint", "dst_endpoint"):
            ep = event.get(endpoint)
            if isinstance(ep, dict) and "ip" in ep and "port" not in ep:
                ip_val = str(ep["ip"])
                # Pattern: IP:port or IP port N
                port_m = _re.search(
                    _re.escape(ip_val) + r'[:\s]+(\d{1,5})\b', raw_log)
                if port_m:
                    port = int(port_m.group(1))
                    if 0 < port <= 65535:
                        ep["port"] = port
                        confidence[f"{endpoint}.port"] = "enrichment"

        # 5. Process name from syslog app[pid]: format
        proc = event.get("process")
        if isinstance(proc, dict):
            # If we have pid but not name, try pre-parsed _app
            if "pid" in proc and "name" not in proc:
                app_name = None
                if preparsed_fields:
                    app_name = preparsed_fields.get("_app")
                if not app_name:
                    # Syslog format: "hostname appname[pid]:"
                    m = _re.search(r'(\S+)\[' + str(proc["pid"]) + r'\]', raw_log)
                    if m:
                        app_name = m.group(1)
                if app_name:
                    proc["name"] = app_name
                    confidence["process.name"] = "enrichment"

            # If we have name but not pid, try pre-parsed _pid
            if "name" in proc and "pid" not in proc and preparsed_fields:
                pid_val = preparsed_fields.get("_pid")
                if pid_val:
                    try:
                        proc["pid"] = int(pid_val)
                        confidence["process.pid"] = "enrichment"
                    except (ValueError, TypeError):
                        pass

        # 6. Actor uid from pre-parsed fields (when name exists but uid doesn't)
        actor = event.get("actor")
        if isinstance(actor, dict):
            actor_user = actor.get("user")
            if isinstance(actor_user, dict) and "name" in actor_user and "uid" not in actor_user:
                # Try to find uid near the username in the log
                name_val = str(actor_user["name"])
                uid_m = _re.search(
                    r'(?:' + _re.escape(name_val) + r'.*?(?:uid|UID)[= ]+(\d+)'
                    r'|(?:uid|UID)[= ]+(\d+).*?' + _re.escape(name_val) + r')',
                    raw_log[:500], _re.I)
                if uid_m:
                    uid_val = uid_m.group(1) or uid_m.group(2)
                    actor_user["uid"] = uid_val
                    confidence["actor.user.uid"] = "enrichment"

        # 7. Status inference from raw log keywords (auth events)
        class_uid = event.get("class_uid", 0)
        if "status" not in event and class_uid in (3002, 3003, 3005):
            # Try explicit keywords first
            status_m = _re.search(
                r'\b((?:success|succeeded|accept(?:ed)?|pass(?:ed)?|Passed|grant(?:ed)?'
                r'|session\s+opened|Logon|logged\s+in|authenticated)'
                r'|(?:fail(?:ed|ure)?|reject(?:ed)?|denied?|block(?:ed)?'
                r'|invalid|unauthorized|session\s+closed|Logoff|logged\s+out))\b',
                raw_log, _re.I)
            if status_m:
                keyword = status_m.group(1).lower()
                if any(keyword.startswith(s) for s in
                       ("success", "accept", "pass", "grant", "session o",
                        "logon", "logged i", "authenticat")):
                    event["status"] = "Success"
                    event["status_id"] = 1
                else:
                    event["status"] = "Failure"
                    event["status_id"] = 2
                confidence["status"] = "enrichment"
                confidence["status_id"] = "enrichment"
            elif event.get("activity_name") == "Logon" or event.get("activity_id") == 1:
                # Logon events without failure indicators are typically successful
                event["status"] = "Success"
                event["status_id"] = 1
                confidence["status"] = "enrichment"
                confidence["status_id"] = "enrichment"

        # 8. src_endpoint.ip from raw log (auth events without IP)
        if class_uid in (3002, 3003) and "src_endpoint" not in event:
            ip_m = _re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', raw_log)
            if ip_m:
                ip_val = ip_m.group(1)
                # Exclude common non-source IPs (localhost, broadcast)
                if ip_val not in ("127.0.0.1", "0.0.0.0", "255.255.255.255"):
                    event["src_endpoint"] = {"ip": ip_val}
                    confidence["src_endpoint.ip"] = "enrichment"

        # 9. OCSF object builders — promote flat fields into required objects
        class_uid = event.get("class_uid", 0)

        # Scheduled Job (1006): job object from process.cmd_line + user
        if class_uid == 1006 and "job" not in event:
            cmd = (event.get("process", {}).get("cmd_line")
                   if isinstance(event.get("process"), dict) else None)
            job_user = event.get("user")
            if cmd or job_user:
                job_obj: dict[str, Any] = {}
                if cmd:
                    job_obj["cmd_line"] = cmd
                    confidence["job.cmd_line"] = "enrichment"
                if job_user:
                    job_obj["created_by"] = job_user
                    confidence["job.created_by"] = "enrichment"
                event["job"] = job_obj

        # Kernel Extension (1002): driver object from module/process info
        if class_uid == 1002 and "driver" not in event:
            proc = event.get("process", {})
            module_name = (proc.get("name") or proc.get("file", {}).get("path")
                           if isinstance(proc, dict) else None)
            if module_name:
                event["driver"] = {"name": module_name}
                confidence["driver.name"] = "enrichment"

        # Module Activity (1005): module object from process info
        if class_uid == 1005 and "module" not in event:
            proc = event.get("process", {})
            if isinstance(proc, dict) and (proc.get("name") or proc.get("file", {}).get("path")):
                event["module"] = {"name": proc.get("name") or proc.get("file", {}).get("path", "")}
                confidence["module.name"] = "enrichment"

        # Account Change (3001): user from actor if available
        if class_uid == 3001 and "user" not in event:
            actor_name = (event.get("actor", {}).get("user", {}).get("name")
                          if isinstance(event.get("actor"), dict) else None)
            if actor_name and isinstance(actor_name, str):
                event["user"] = {"name": actor_name}
                confidence["user.name"] = "enrichment"

        # Group Management (3004): entity from user/group
        if class_uid == 3004 and "entity" not in event:
            group = event.get("group")
            user = event.get("user")
            if group:
                event["entity"] = group if isinstance(group, dict) else {"name": str(group)}
                confidence["entity.name"] = "enrichment"
            elif user and isinstance(user, str):
                event["entity"] = {"name": user}
                confidence["entity.name"] = "enrichment"

        # API Activity (6003): api object from activity_name/operation
        if class_uid == 6003 and "api" not in event:
            operation = event.get("activity_name") or event.get("api_operation")
            if operation and isinstance(operation, str):
                event["api"] = {"operation": operation}
                confidence["api.operation"] = "enrichment"

        # User Access Management (3005): privileges from message if available
        if class_uid == 3005 and "privileges" not in event:
            msg = event.get("message", "")
            if isinstance(msg, str) and len(msg) > 5:
                event["privileges"] = [msg[:200]]
                confidence["privileges"] = "enrichment"

    @staticmethod
    def _scrub_invalid_types(event: dict[str, Any], confidence: dict[str, str]) -> None:
        """Validate and coerce typed fields. Remove values that can't be fixed.

        Catches: hostnames in IP fields, garbage in port fields, hex PIDs, etc.
        Runs after extraction, before returning ExtractionResult.
        """
        import ipaddress as _ipa

        def _scrub(obj: dict, prefix: str = "") -> list[str]:
            """Walk event, coerce where possible, return paths to remove."""
            to_remove: list[str] = []
            for k, v in list(obj.items()):
                path = f"{prefix}.{k}" if prefix else k
                if isinstance(v, dict):
                    to_remove.extend(_scrub(v, path))
                    continue

                # IP validation
                if k == "ip" and isinstance(v, str):
                    try:
                        _ipa.ip_address(v.strip("[]"))
                    except ValueError:
                        to_remove.append(path)

                # Port validation + coercion
                elif k == "port":
                    if isinstance(v, int):
                        if not (0 <= v <= 65535):
                            to_remove.append(path)
                    elif isinstance(v, str):
                        to_remove.append(path)

                # PID/TID coercion — hex strings like "0x3e7" → 999
                elif k in ("pid", "tid") and isinstance(v, str):
                    try:
                        if v.startswith("0x") or v.startswith("0X"):
                            obj[k] = int(v, 16)
                        elif v.isdigit():
                            obj[k] = int(v)
                        else:
                            to_remove.append(path)
                    except (ValueError, TypeError):
                        to_remove.append(path)

            return to_remove

        removals = _scrub(event)
        for path in removals:
            parts = path.split(".")
            obj = event
            for p in parts[:-1]:
                if isinstance(obj, dict) and p in obj:
                    obj = obj[p]
                else:
                    break
            else:
                if isinstance(obj, dict) and parts[-1] in obj:
                    del obj[parts[-1]]
                    confidence.pop(path, None)

    def _try_preparse_alias_fallback(
        self,
        raw_log: str,
        log_format: LogFormat,
        class_uid: int,
        class_name: str,
        start_time: float,
    ) -> ExtractionResult | None:
        """Fallback for non-JSON logs: pre-parse fields and map via alias table."""
        from shrike.extractor.preparsers import preparse as _preparse
        preparsed = _preparse(raw_log, log_format)
        if preparsed is None or len(preparsed.fields) < 2:
            return None

        try:
            from shrike.extractor.field_mapper import FieldMapper
            if not hasattr(PatternExtractor, '_field_mapper_instance'):
                PatternExtractor._field_mapper_instance = FieldMapper()
            mapper = PatternExtractor._field_mapper_instance
        except ImportError:
            return None

        event: dict[str, Any] = {
            "class_uid": class_uid,
            "class_name": class_name,
            "activity_id": 0,
            "severity_id": 1,
            "category_uid": class_uid // 1000,
        }
        confidence: dict[str, str] = {}

        for k, v in preparsed.fields.items():
            if k.startswith("_"):
                continue
            ocsf_path = mapper._aliases.get(k)
            if ocsf_path and v is not None and str(v) not in ("", "None", "null"):
                _set_nested(event, ocsf_path, _coerce_value(str(v)))
                confidence[ocsf_path] = "alias"

        if len(confidence) < 3:
            return None

        # Post-extraction enrichment
        self._enrich_ocsf_required(
            event, raw_log, log_format, confidence,
            preparsed_fields=preparsed.fields)
        self._scrub_invalid_types(event, confidence)

        elapsed = (time.monotonic() - start_time) * 1000
        return ExtractionResult(
            event=event,
            class_uid=class_uid,
            class_name=class_name,
            raw_log=raw_log,
            extraction_time_ms=elapsed,
            confidence=confidence,
        )

    def _match_pattern(
        self,
        pattern: PatternDef,
        raw_log: str,
        log_format: LogFormat,
    ) -> dict[str, Any] | None:
        """Test one pattern against the log. Returns extracted groups or None."""
        # Check 'contains' first (fast string check)
        if pattern.contains and pattern.contains not in raw_log:
            return None

        # JSON-based matching
        if pattern.json_has or pattern.json_match:
            try:
                data = json.loads(raw_log.strip())
                if not isinstance(data, dict):
                    return None
            except (json.JSONDecodeError, ValueError):
                return None

            if pattern.json_has:
                for field_name in pattern.json_has:
                    if field_name not in data:
                        return None

            if pattern.json_match:
                for key, expected in pattern.json_match.items():
                    if data.get(key) != expected and str(data.get(key)) != str(expected):
                        return None

            return {"_json_data": data}

        # Regex matching
        if pattern.regex:
            m = pattern.regex.search(raw_log)
            if m:
                return m.groupdict()

        return None

    def _build_event(
        self,
        match: dict[str, Any],
        pattern: PatternDef,
        raw_log: str,
        confidence: dict[str, str] | None = None,
        preparsed_fields: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Build OCSF event dict from match using field_map and static fields."""
        event: dict[str, Any] = {}
        if confidence is None:
            confidence = {}

        # Set class metadata
        event["class_uid"] = pattern.ocsf_class_uid
        event["class_name"] = pattern.ocsf_class_name

        # Apply static fields
        for key, value in pattern.static_fields.items():
            _set_nested(event, key, value)

        # Apply field map
        json_data = match.get("_json_data")
        for source_field, ocsf_path in pattern.field_map.items():
            value = None
            if json_data:
                # Navigate dotted source paths in JSON data
                value = json_data
                for part in source_field.split("."):
                    if isinstance(value, dict):
                        value = value.get(part)
                    else:
                        value = None
                        break
            elif source_field in match:
                value = match[source_field]
            elif preparsed_fields and source_field in preparsed_fields:
                value = preparsed_fields[source_field]

            if value is not None:
                _set_nested(event, ocsf_path, _coerce_value(str(value), ocsf_path))
                confidence[ocsf_path] = "pattern"

        # Apply severity map if defined
        if pattern.severity_map:
            self._apply_severity_map(event, pattern.severity_map, match, json_data)

        # Auto-populate commonly-required OCSF fields if missing
        event.setdefault("activity_id", 0)  # Unknown
        event.setdefault("severity_id", 1)  # Informational
        event.setdefault("category_uid", pattern.ocsf_class_uid // 1000)

        # Auto-extract from JSON data for common required fields
        if json_data:
            self._auto_extract_json(event, json_data, pattern.ocsf_class_uid, confidence)

        # Try to extract missing required fields from raw log via regex
        # Only set if we find a REAL value — never set "unknown"
        import re as _re
        if "user" not in event and pattern.ocsf_class_uid in (3002, 3001, 3003, 3005):
            user_m = _re.search(r'(?:user[= ]|for\s+)(\S+)', raw_log, _re.I)
            if user_m:
                event["user"] = user_m.group(1).rstrip("'\"")
                if confidence is not None:
                    confidence["user"] = "pattern"

        # For Application Lifecycle, add 'app' from source_app in syslog if available
        if pattern.ocsf_class_uid == 6002 and "app" not in event:
            import re as _re
            app_match = _re.search(r"(?:Started|Stopped|Failed)\s+(.+?)(?:\s*[-.]|$)", raw_log)
            if app_match:
                event["app"] = {"name": app_match.group(1).strip().rstrip(".")}
                if confidence is not None:
                    confidence["app.name"] = "pattern"

        # Extract timestamp from syslog header if not set
        if "time" not in event:
            # Try common syslog timestamp patterns
            ts_match = re.match(
                r"(?:<\d+>(?:\d+\s+)?)?(\d{4}-\d{2}-\d{2}T\S+|"
                r"\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})",
                raw_log,
            )
            if ts_match:
                event["time"] = ts_match.group(1)
                if confidence is not None:
                    confidence["time"] = "pattern"

        return event

    @staticmethod
    def _auto_extract_json(event: dict, json_data: dict, class_uid: int,
                           confidence: dict | None = None) -> None:
        """Auto-extract common JSON fields into OCSF required fields.

        This fills in required fields that the pattern's field_map missed.
        Uses FieldMapper for alias + fuzzy matching, then falls back to
        hardcoded lookups for common patterns.
        """
        # Try FieldMapper first for comprehensive mapping
        try:
            from shrike.extractor.field_mapper import FieldMapper
            if not hasattr(PatternExtractor, '_field_mapper_instance'):
                PatternExtractor._field_mapper_instance = FieldMapper()
            mapper = PatternExtractor._field_mapper_instance

            # Collect all JSON fields first, then batch-map
            # Cap depth at 3 to prevent walking into deeply nested metadata
            # (Docker container attrs, K8s labels, etc.)
            all_fields: list[tuple[str, str, Any]] = []  # (full_key, leaf_key, value)
            def collect_fields(obj, prefix="", depth=0):
                if depth > 3 or not isinstance(obj, dict):
                    return
                for k, v in obj.items():
                    full_key = f"{prefix}.{k}" if prefix else k
                    if v is not None and str(v) not in ("", "None", "null"):
                        # Skip dict/list values at leaf level — only collect scalars
                        if not isinstance(v, (dict, list)):
                            all_fields.append((full_key, k, v))
                    if isinstance(v, dict):
                        collect_fields(v, full_key, depth + 1)
            collect_fields(json_data)

            # Map all fields — alias and fuzzy first (instant)
            for full_key, leaf_key, value in all_fields:
                ocsf_path = mapper._aliases.get(full_key) or mapper._aliases.get(leaf_key)
                conf = "alias"
                if not ocsf_path:
                    ocsf_path = mapper._fuzzy_match(full_key, value)
                    conf = "fuzzy"
                if ocsf_path:
                    # Don't overwrite existing values
                    parts = ocsf_path.split(".")
                    existing = event
                    found = True
                    for p in parts:
                        if isinstance(existing, dict) and p in existing:
                            existing = existing[p]
                        else:
                            found = False
                            break
                    if not found:
                        _set_nested(event, ocsf_path, value)
                        if confidence is not None:
                            confidence[ocsf_path] = conf

            # Embedding-based batch mapping for remaining unmapped fields
            try:
                emb_mapper = mapper._get_embedding_mapper()
                if emb_mapper:
                    unmapped = [(fk, lk, v) for fk, lk, v in all_fields
                                if not (mapper._aliases.get(fk) or mapper._aliases.get(lk)
                                       or mapper._fuzzy_match(fk, v))]
                    if unmapped:
                        field_names = [fk for fk, _, _ in unmapped]
                        results = emb_mapper.map_fields_batch(field_names)
                        for (fk, lk, v), (ocsf_path, score) in zip(unmapped, results):
                            if ocsf_path:
                                parts = ocsf_path.split(".")
                                existing = event
                                found = True
                                for p in parts:
                                    if isinstance(existing, dict) and p in existing:
                                        existing = existing[p]
                                    else:
                                        found = False
                                        break
                                if not found:
                                    _set_nested(event, ocsf_path, v)
                                    if confidence is not None:
                                        confidence[ocsf_path] = "embedding"
            except Exception:
                pass  # Embedding mapper optional
        except ImportError:
            pass

        def _get(keys: list[str]) -> Any:
            """Try multiple JSON key names, return first found value."""
            for k in keys:
                if "." in k:
                    val = json_data
                    for part in k.split("."):
                        if isinstance(val, dict):
                            val = val.get(part)
                        else:
                            val = None
                            break
                    if val is not None:
                        return val
                elif k in json_data:
                    return json_data[k]
            return None

        # Time
        if "time" not in event:
            ts = _get(["@timestamp", "timestamp", "time", "Time", "ts",
                       "activityDateTime", "EventTime", "TimeCreated",
                       "TimeGenerated", "date", "created_at"])
            if ts is not None:
                event["time"] = str(ts)
                if confidence is not None:
                    confidence["time"] = "auto"

        # User (required for Auth 3002, AccessMgmt 3005)
        if "user" not in event:
            u = _get(["user", "UserName", "TargetUserName", "userName",
                      "user.name", "SubjectUserName", "actorDetails",
                      "userIdentity.userName", "usr", "usrName",
                      "Actor", "identity", "userEmail", "email",
                      "account", "principal"])
            if u is not None:
                # Only set scalar values — not nested dicts (Docker metadata, etc.)
                if isinstance(u, str):
                    event["user"] = u
                    if confidence is not None:
                        confidence["user"] = "auto"
                elif isinstance(u, dict) and "name" in u and isinstance(u["name"], str):
                    event["user"] = u["name"]
                    if confidence is not None:
                        confidence["user"] = "auto"

        # Source endpoint
        if "src_endpoint" not in event:
            ip = _get(["src_ip", "source_ip", "IpAddress", "sourceIPAddress",
                       "client_ip", "client.ip", "source.ip", "remote_addr",
                       "src", "SrcAddr", "addr", "callerIpAddress",
                       "properties.callerIpAddress", "userAgent"])
            if ip is not None:
                event["src_endpoint"] = {"ip": str(ip)}
                if confidence is not None:
                    confidence["src_endpoint.ip"] = "auto"

        # Destination endpoint
        if "dst_endpoint" not in event:
            ip = _get(["dest_ip", "destination_ip", "dst", "DstAddr",
                       "destination.ip", "dest", "server_ip"])
            if ip is not None:
                event["dst_endpoint"] = {"ip": str(ip)}
                if confidence is not None:
                    confidence["dst_endpoint.ip"] = "auto"

        # Device/host
        if "device" not in event:
            host = _get(["Computer", "hostname", "host", "host.name",
                        "LogHost", "device", "node", "agent.hostname"])
            if host is not None:
                h = str(host) if not isinstance(host, dict) else host.get("name", str(host))
                event["device"] = {"hostname": h}

        # Process (required for Process Activity 1007)
        if class_uid == 1007 and "process" not in event:
            proc: dict[str, Any] = {}
            name = _get(["process.name", "NewProcessName", "Image",
                        "ProcessName", "process_name", "exe"])
            if name is not None:
                proc["name"] = str(name)
            pid = _get(["process.pid", "ProcessID", "ProcessId", "pid"])
            if pid is not None:
                proc["pid"] = pid
            cmd = _get(["CommandLine", "process.command_line", "cmdline",
                       "command_line", "process.args"])
            if cmd is not None:
                proc["cmd_line"] = str(cmd)
            if proc:
                event["process"] = proc

        # App (required for Application Lifecycle 6002)
        if class_uid == 6002 and "app" not in event:
            app = _get(["app", "application", "service", "program",
                       "agent.type", "event.module", "kubernetes.container.name",
                       "container_name", "source", "SourceName", "Type",
                       "scope", "Action", "o365.Workload", "event.dataset"])
            if app is not None:
                a = str(app) if not isinstance(app, dict) else app.get("name", str(app))
                event["app"] = {"name": a}
            else:
                # Fallback: try msg field for app name, or use EventID
                msg = _get(["msg", "message", "description"])
                if msg and isinstance(msg, str) and len(msg) < 100:
                    event["app"] = {"name": msg.split(" - ")[0].split(":")[0].strip()[:50]}
                elif "EventID" in json_data:
                    event["app"] = {"name": f"Windows (EventID {json_data['EventID']})"}

        # API (required for API Activity 6003)
        if class_uid == 6003 and "api" not in event:
            op = _get(["eventName", "operationName", "action", "api.operation",
                      "method", "request.method", "activity", "kind",
                      "category", "events", "resultType"])
            if op is not None:
                event["api"] = {"operation": str(op)}
            else:
                # Fallback — required field, set default
                event["api"] = {"operation": "Unknown"}

        # Ensure src_endpoint for API Activity (required)
        if class_uid == 6003 and "src_endpoint" not in event:
            # Try harder for IP-like values
            for k, v in json_data.items():
                if isinstance(v, str) and len(v) < 50:
                    import re as _re
                    if _re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", v):
                        event["src_endpoint"] = {"ip": v}
                        break
            if "src_endpoint" not in event:
                event["src_endpoint"] = {"ip": "unknown"}

        # Ensure actor for API Activity (required)
        if class_uid == 6003 and "actor" not in event:
            event["actor"] = {"user": {"name": "unknown"}}

        # Finding info (for Detection Finding 2004)
        if class_uid == 2004 and "finding_info" not in event:
            title = _get(["rule.name", "alert.signature", "signature",
                         "rule_name", "finding", "detection_name", "title"])
            if title is not None:
                event["finding_info"] = {"title": str(title)}

        # Privileges (required for User Access Management 3005)
        if class_uid == 3005 and "privileges" not in event:
            privs = _get(["PrivilegeList", "privileges", "permissions",
                         "Privileges", "access", "rights"])
            if privs is not None:
                event["privileges"] = [str(privs)] if isinstance(privs, str) else privs
            else:
                event["privileges"] = ["Unknown"]

        # Finding (required for Security Finding 2001)
        if class_uid == 2001 and "finding" not in event:
            title = _get(["title", "name", "finding", "description", "msg", "message"])
            event["finding"] = {"title": str(title) if title else "Security Finding"}
            event.setdefault("state_id", 1)

        # Email (required for Email Activity 4009)
        if class_uid == 4009 and "email" not in event:
            subj = _get(["subject", "Subject", "email_subject", "title"])
            frm = _get(["from", "sender", "mail_from", "envelope_from"])
            to = _get(["to", "recipient", "rcpt_to", "envelope_to"])
            email_obj = {}
            if subj: email_obj["subject"] = str(subj)
            if frm: email_obj["from"] = str(frm)
            if to: email_obj["to"] = [str(to)] if isinstance(to, str) else to
            event["email"] = email_obj if email_obj else {"subject": "Unknown"}
            event.setdefault("direction_id", 0)  # Unknown

        # Actor
        if "actor" not in event:
            actor_name = _get(["SubjectUserName", "actor.user.name",
                              "actor", "initiator", "caller", "identity",
                              "userEmail", "callerIdentity"])
            if actor_name is not None:
                a = str(actor_name) if not isinstance(actor_name, dict) else actor_name
                if isinstance(a, str):
                    event["actor"] = {"user": {"name": a}}
                else:
                    event["actor"] = a

        # Message
        if "message" not in event:
            msg = _get(["message", "msg", "description", "log_message",
                       "event.reason", "Description"])
            if msg is not None:
                event["message"] = str(msg)[:500]

        # Severity from string
        if event.get("severity_id") == 1:  # Still default
            sev = _get(["severity", "level", "priority", "Severity"])
            if sev is not None:
                sev_str = str(sev).lower()
                sev_map = {"critical": 5, "high": 4, "medium": 3, "low": 2,
                          "info": 1, "informational": 1, "warning": 3, "warn": 3,
                          "error": 4, "fatal": 6, "debug": 1}
                event["severity_id"] = sev_map.get(sev_str, 1)

    def _apply_severity_map(
        self,
        event: dict,
        severity_map: dict,
        match: dict,
        json_data: dict | None,
    ) -> None:
        """Apply conditional severity mapping."""
        field_name = severity_map.get("field", "")
        value = None
        if json_data and field_name in json_data:
            value = json_data[field_name]
        elif field_name in match:
            value = match[field_name]
        elif field_name in event:
            value = event[field_name]

        if value is None:
            return

        try:
            num_value = int(value)
        except (ValueError, TypeError):
            return

        for rule in severity_map.get("rules", []):
            if "range" in rule:
                low, high = rule["range"]
                if low <= num_value <= high:
                    event["severity_id"] = rule["severity_id"]
                    return
            if "value" in rule:
                if num_value == rule["value"]:
                    event["severity_id"] = rule["severity_id"]
                    return

    @property
    def pattern_count(self) -> int:
        return len(self._patterns)

    @property
    def sources(self) -> list[str]:
        return sorted(set(p.source for p in self._patterns))
