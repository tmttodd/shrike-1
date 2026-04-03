#!/usr/bin/env python3
"""Build NER training data for security entity extraction from raw logs.

Takes ground truth classification records, runs pattern extraction, and
generates BIO-tagged training data for fine-tuning SecureBERT 2.0.

Entity types:
  IP, PORT, USER, HOSTNAME, PROCESS, PID, PATH, TIMESTAMP, PROTOCOL,
  ACTION, STATUS, FINDING, SID, MAC, EMAIL

Outputs:
  1. training/ner_training_bio.txt     — CoNLL-style BIO tags (token\ttag per line)
  2. training/ner_training_hf.jsonl    — HuggingFace datasets format
  3. training/ner_training_stats.json  — Statistics report

Usage:
    python3 training/build_ner_training.py
"""

from __future__ import annotations

import json
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from shrike.detector.format_detector import LogFormat, detect_format
from shrike.evaluate.types import walk_event
from shrike.extractor.pattern_extractor import PatternExtractor


# ---------------------------------------------------------------------------
# OCSF field path -> NER entity type mapping
# ---------------------------------------------------------------------------

# Mapping from OCSF field path suffixes/patterns to NER entity types.
# Checked in order: first match wins.
OCSF_TO_NER: list[tuple[str, str]] = [
    # IP addresses
    ("src_endpoint.ip", "IP"),
    ("dst_endpoint.ip", "IP"),
    ("device.ip", "IP"),
    ("endpoint.ip", "IP"),
    (".ip", "IP"),
    ("ip_address", "IP"),

    # Ports
    ("src_endpoint.port", "PORT"),
    ("dst_endpoint.port", "PORT"),
    (".port", "PORT"),

    # Users
    ("actor.user.name", "USER"),
    ("actor.user.uid", "USER"),
    ("user.name", "USER"),
    ("user.uid", "USER"),
    ("user", "USER"),
    ("acct", "USER"),
    ("recipient", "USER"),
    ("sender", "USER"),

    # Email
    ("email", "EMAIL"),
    ("email_addr", "EMAIL"),
    (".email", "EMAIL"),

    # Hostnames
    ("device.hostname", "HOSTNAME"),
    ("src_endpoint.hostname", "HOSTNAME"),
    ("dst_endpoint.hostname", "HOSTNAME"),
    (".hostname", "HOSTNAME"),
    (".domain", "HOSTNAME"),

    # Processes
    ("process.name", "PROCESS"),
    ("process.cmd_line", "PROCESS"),
    ("actor.process.name", "PROCESS"),
    ("app.name", "PROCESS"),

    # PIDs
    ("process.pid", "PID"),
    ("actor.process.pid", "PID"),

    # Paths
    ("process.file.path", "PATH"),
    ("file.path", "PATH"),
    ("file.name", "PATH"),
    (".path", "PATH"),
    (".url.path", "PATH"),
    ("http_request.url.path", "PATH"),

    # Timestamps
    ("time", "TIMESTAMP"),
    ("timestamp", "TIMESTAMP"),
    (".time", "TIMESTAMP"),
    ("start_time", "TIMESTAMP"),
    ("end_time", "TIMESTAMP"),

    # Protocols
    ("connection_info.protocol_name", "PROTOCOL"),
    (".protocol", "PROTOCOL"),
    ("auth_protocol", "PROTOCOL"),
    ("network.protocol", "PROTOCOL"),

    # Actions
    ("activity_name", "ACTION"),
    ("action", "ACTION"),

    # Status
    ("status", "STATUS"),
    ("status_detail", "STATUS"),
    ("disposition", "STATUS"),

    # Findings / alerts
    ("finding.title", "FINDING"),
    ("finding.desc", "FINDING"),
    ("finding_info.title", "FINDING"),
    ("rule.name", "FINDING"),
    # NOTE: "message" is intentionally excluded — it contains the entire
    # syslog message body which is too broad for a FINDING entity.

    # Signature IDs
    ("finding.uid", "SID"),
    (".rule_id", "SID"),
    (".signature_id", "SID"),
    ("metadata.uid", "SID"),

    # MAC addresses
    (".mac", "MAC"),
    ("mac_address", "MAC"),

    # HTTP method — treat as ACTION
    ("http_request.http_method", "ACTION"),

    # HTTP status code — treat as STATUS
    ("http_response.code", "STATUS"),

    # Severity — skip (usually a numeric ID, not a token)
    ("severity_id", None),
    ("severity", None),

    # Category/class metadata — skip
    ("class_uid", None),
    ("class_name", None),
    ("category_uid", None),
    ("category_name", None),
    ("activity_id", None),
    ("type_uid", None),
    ("type_name", None),
    ("status_id", None),
]

# Fields that are metadata set by the pipeline, not extracted from the log.
# Always skip these for NER purposes.
SKIP_FIELDS = frozenset({
    "class_uid", "class_name", "category_uid", "category_name",
    "activity_id", "activity_name", "severity_id", "severity",
    "type_uid", "type_name", "status_id",
})

# Confidence sources that indicate the value was NOT extracted from the log
SKIP_CONFIDENCE = frozenset({"static", "default"})


def map_ocsf_to_ner(field_path: str) -> str | None:
    """Map an OCSF dotted field path to a NER entity type.

    Returns the NER type string, or None to skip this field.
    """
    for suffix, ner_type in OCSF_TO_NER:
        if field_path == suffix or field_path.endswith("." + suffix) or field_path.endswith(suffix):
            return ner_type
    return None


# ---------------------------------------------------------------------------
# Value-to-span finding
# ---------------------------------------------------------------------------

def find_value_spans(raw_log: str, value: str) -> list[tuple[int, int]]:
    """Find all character-level (start, end) spans of value in raw_log.

    Tries exact match first, then case-insensitive.
    Returns list of (start, end) tuples.
    """
    val_str = str(value).strip()
    if not val_str or len(val_str) <= 1:
        return []

    spans = []
    # Exact match
    start = 0
    while True:
        idx = raw_log.find(val_str, start)
        if idx == -1:
            break
        spans.append((idx, idx + len(val_str)))
        start = idx + 1

    if spans:
        return spans

    # Case-insensitive fallback
    lower_log = raw_log.lower()
    lower_val = val_str.lower()
    start = 0
    while True:
        idx = lower_log.find(lower_val, start)
        if idx == -1:
            break
        spans.append((idx, idx + len(val_str)))
        start = idx + 1

    return spans


# ---------------------------------------------------------------------------
# Regex-based entity extraction (supplement pattern extractor)
# ---------------------------------------------------------------------------

# These regexes catch common security entities that pattern extraction may miss.
ENTITY_REGEXES: list[tuple[str, re.Pattern]] = [
    ("IP", re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b'
    )),
    ("IP", re.compile(  # IPv6 (simplified — common compressed forms)
        r'(?<![:\w])(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}(?![:\w])'
    )),
    ("IP", re.compile(  # IPv6 with :: compression
        r'(?<![:\w])(?:[0-9a-fA-F]{1,4}:)*::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}(?![:\w])'
    )),
    ("MAC", re.compile(
        r'\b(?:[0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}\b'
    )),
    ("EMAIL", re.compile(
        r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b'
    )),
    ("PORT", re.compile(
        r'(?:port|PORT)[= :]+(\d{1,5})\b'
    )),
    ("PID", re.compile(
        r'(?:pid|PID)[= :]+(\d+)\b'
    )),
    ("PID", re.compile(
        r'\w+\[(\d+)\]:'  # syslog app[pid]: format
    )),
    ("PATH", re.compile(
        r'(?:/[\w.\-]+){2,}'  # Unix paths with 2+ components
    )),
    ("PROTOCOL", re.compile(
        r'\b(?:TCP|UDP|ICMP|SSH|HTTP|HTTPS|FTP|DNS|SMTP|TLS|SSL|NTP|SNMP|RDP|LDAP|DHCP)\b',
        re.IGNORECASE,
    )),
]


def _is_likely_ip(text: str, raw_log: str, start: int) -> bool:
    """Validate that a matched string is actually an IP, not a time or version."""
    # Check for HH:MM:SS pattern (time, not IP)
    if re.match(r'^\d{1,2}:\d{2}:\d{2}$', text):
        return False
    # Check for version-like patterns (e.g., "2.4.46")
    if start > 0 and raw_log[start - 1] == '/':
        return False
    # Must have dots for IPv4
    if '.' in text and ':' not in text:
        octets = text.split('.')
        if len(octets) == 4:
            # At least one octet should be > 23 to distinguish from time
            # OR the whole string looks like a.b.c.d with proper context
            try:
                vals = [int(o) for o in octets]
                if all(v <= 23 for v in vals):
                    # Could be a time; check context — is it preceded by date-like stuff?
                    before = raw_log[max(0, start - 5):start]
                    if re.search(r'\d{4}[-/]', before) or re.search(r'\d{2}[-/]\w+[-/]', before):
                        return False
            except ValueError:
                return False
    return True


def regex_extract_entities(raw_log: str) -> list[tuple[str, int, int]]:
    """Extract entities using regex patterns.

    Returns list of (ner_type, start, end) tuples.
    """
    entities = []
    for ner_type, pattern in ENTITY_REGEXES:
        for m in pattern.finditer(raw_log):
            # If the pattern has a group, use group 1 (the captured value)
            if m.lastindex and m.lastindex >= 1:
                start, end = m.start(1), m.end(1)
                matched_text = m.group(1)
            else:
                start, end = m.start(), m.end()
                matched_text = m.group()

            # Validate IPs to filter false positives
            if ner_type == "IP" and not _is_likely_ip(matched_text, raw_log, start):
                continue

            # Validate ports are in valid range
            if ner_type == "PORT":
                try:
                    port_val = int(matched_text)
                    if port_val < 1 or port_val > 65535:
                        continue
                except ValueError:
                    continue

            entities.append((ner_type, start, end))
    return entities


# ---------------------------------------------------------------------------
# BIO tag generation
# ---------------------------------------------------------------------------

# Tokenizer: split on whitespace, preserving character offsets
def whitespace_tokenize(text: str) -> list[tuple[str, int, int]]:
    """Tokenize by whitespace, returning (token, char_start, char_end) tuples."""
    tokens = []
    for m in re.finditer(r'\S+', text):
        tokens.append((m.group(), m.start(), m.end()))
    return tokens


def spans_to_bio_tags(
    tokens: list[tuple[str, int, int]],
    entity_spans: list[tuple[str, int, int]],
) -> list[str]:
    """Convert entity spans to BIO tags aligned to tokens.

    Args:
        tokens: list of (token_text, char_start, char_end)
        entity_spans: list of (ner_type, char_start, char_end)

    Returns:
        list of BIO tags, one per token
    """
    tags = ["O"] * len(tokens)

    # Sort spans by start position, longest first for ties
    sorted_spans = sorted(entity_spans, key=lambda s: (s[1], -(s[2] - s[1])))

    # Track which tokens are already tagged (prevent overlaps)
    tagged = set()

    for ner_type, span_start, span_end in sorted_spans:
        first_token = True
        for i, (tok_text, tok_start, tok_end) in enumerate(tokens):
            if i in tagged:
                continue
            # Token overlaps with entity span
            if tok_start < span_end and tok_end > span_start:
                if first_token:
                    tags[i] = f"B-{ner_type}"
                    first_token = False
                else:
                    tags[i] = f"I-{ner_type}"
                tagged.add(i)

    return tags


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def extract_entities_from_record(
    raw_log: str,
    class_uid: int,
    class_name: str,
    extractor: PatternExtractor,
) -> list[tuple[str, int, int]]:
    """Extract NER entity spans from a single log record.

    Combines pattern extraction (OCSF-mapped) with regex fallback.
    Returns deduplicated list of (ner_type, char_start, char_end).
    """
    entities: list[tuple[str, int, int]] = []

    # Detect format
    fmt = detect_format(raw_log)

    # Try pattern extraction
    result = extractor.try_extract(raw_log, fmt, class_uid=class_uid, class_name=class_name)

    if result and result.event:
        confidence = result.confidence or {}
        for field_path, value in walk_event(result.event):
            # Skip metadata fields
            leaf = field_path.rsplit(".", 1)[-1]
            if leaf in SKIP_FIELDS or field_path in SKIP_FIELDS:
                continue

            # Skip static/default confidence values
            if confidence.get(field_path) in SKIP_CONFIDENCE:
                continue

            # Map to NER type
            ner_type = map_ocsf_to_ner(field_path)
            if ner_type is None:
                continue

            # Find value in raw log
            val_str = str(value)

            # Skip very long values (e.g., full message body) — they produce
            # noisy multi-token FINDING spans that hurt model quality
            if len(val_str) > 120:
                continue

            spans = find_value_spans(raw_log, val_str)
            if spans:
                # Use first occurrence (most likely the source)
                start, end = spans[0]
                entities.append((ner_type, start, end))

    # Supplement with regex-based extraction
    regex_entities = regex_extract_entities(raw_log)

    # Merge: prefer pattern-extracted entities (higher confidence)
    # Only add regex entities if they don't overlap with existing ones
    for ner_type, start, end in regex_entities:
        overlaps = False
        for _, es, ee in entities:
            if start < ee and end > es:
                overlaps = True
                break
        if not overlaps:
            entities.append((ner_type, start, end))

    return entities


def process_ground_truth(
    gt_path: Path,
    extractor: PatternExtractor,
) -> tuple[list[dict], list[dict], Counter]:
    """Process all ground truth records and generate NER training data.

    Returns:
        bio_records: list of {"tokens": [...], "tags": [...]} for BIO output
        hf_records: list of HuggingFace format records
        entity_counts: Counter of entity type occurrences
    """
    bio_records = []
    hf_records = []
    entity_counts: Counter = Counter()
    total = 0
    with_entities = 0
    skipped_json_only = 0
    extraction_used = 0

    with open(gt_path) as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue

            raw_log = rec.get("raw_log", "")
            class_uid = rec.get("class_uid", 0)
            class_name = rec.get("class_name", "")
            total += 1

            # Skip very short logs
            if len(raw_log) < 10:
                continue

            # For JSON logs that are structured data, we still want to extract
            # entities from the JSON values (IPs, users, etc.)
            entities = extract_entities_from_record(
                raw_log, class_uid, class_name, extractor,
            )

            if not entities:
                continue

            with_entities += 1

            # Count entity types
            for ner_type, _, _ in entities:
                entity_counts[ner_type] += 1

            # Tokenize
            tokens = whitespace_tokenize(raw_log)
            if not tokens:
                continue

            # Generate BIO tags
            tags = spans_to_bio_tags(tokens, entities)

            token_texts = [t[0] for t in tokens]

            # BIO record
            bio_records.append({
                "tokens": token_texts,
                "tags": tags,
            })

            # HuggingFace format: tokens, ner_tags (as integers), plus char offsets
            hf_records.append({
                "id": line_num,
                "tokens": token_texts,
                "ner_tags": tags,
                "char_offsets": [(t[1], t[2]) for t in tokens],
                "raw_log": raw_log,
                "class_uid": class_uid,
                "class_name": class_name,
            })

            if line_num % 1000 == 0:
                print(f"  Processed {line_num} records, {with_entities} with entities...",
                      file=sys.stderr)

    return bio_records, hf_records, entity_counts


# NER label set for the model
NER_LABELS = [
    "O",
    "B-IP", "I-IP",
    "B-PORT", "I-PORT",
    "B-USER", "I-USER",
    "B-HOSTNAME", "I-HOSTNAME",
    "B-PROCESS", "I-PROCESS",
    "B-PID", "I-PID",
    "B-PATH", "I-PATH",
    "B-TIMESTAMP", "I-TIMESTAMP",
    "B-PROTOCOL", "I-PROTOCOL",
    "B-ACTION", "I-ACTION",
    "B-STATUS", "I-STATUS",
    "B-FINDING", "I-FINDING",
    "B-SID", "I-SID",
    "B-MAC", "I-MAC",
    "B-EMAIL", "I-EMAIL",
]

LABEL_TO_ID = {label: i for i, label in enumerate(NER_LABELS)}


def main():
    start_time = time.monotonic()

    gt_path = PROJECT_ROOT / "data" / "ground_truth" / "classification_ground_truth.jsonl"
    if not gt_path.exists():
        print(f"ERROR: Ground truth not found at {gt_path}", file=sys.stderr)
        sys.exit(1)

    out_dir = PROJECT_ROOT / "training"
    out_dir.mkdir(exist_ok=True)

    bio_path = out_dir / "ner_training_bio.txt"
    hf_path = out_dir / "ner_training_hf.jsonl"
    stats_path = out_dir / "ner_training_stats.json"

    print(f"Loading pattern extractor...", file=sys.stderr)
    extractor = PatternExtractor()
    print(f"  Loaded {len(extractor._patterns)} patterns", file=sys.stderr)

    print(f"Processing ground truth: {gt_path}", file=sys.stderr)
    bio_records, hf_records, entity_counts = process_ground_truth(gt_path, extractor)

    # Write BIO format
    print(f"Writing BIO format to {bio_path}...", file=sys.stderr)
    with open(bio_path, "w") as f:
        for rec in bio_records:
            for tok, tag in zip(rec["tokens"], rec["tags"]):
                f.write(f"{tok}\t{tag}\n")
            f.write("\n")  # Blank line between sentences

    # Write HuggingFace format
    print(f"Writing HuggingFace format to {hf_path}...", file=sys.stderr)
    with open(hf_path, "w") as f:
        for rec in hf_records:
            # Convert string tags to integer IDs for HF
            tag_ids = [LABEL_TO_ID.get(t, 0) for t in rec["ner_tags"]]
            hf_out = {
                "id": rec["id"],
                "tokens": rec["tokens"],
                "ner_tags": tag_ids,
                "ner_tag_names": rec["ner_tags"],
                "class_uid": rec["class_uid"],
                "class_name": rec["class_name"],
            }
            f.write(json.dumps(hf_out) + "\n")

    # Compute stats
    total_tokens = sum(len(r["tokens"]) for r in bio_records)
    tagged_tokens = sum(
        sum(1 for t in r["tags"] if t != "O")
        for r in bio_records
    )
    tag_distribution = Counter()
    for rec in bio_records:
        for tag in rec["tags"]:
            tag_distribution[tag] += 1

    elapsed = time.monotonic() - start_time

    stats = {
        "total_ground_truth_records": sum(1 for _ in open(gt_path)),
        "records_with_entities": len(bio_records),
        "total_tokens": total_tokens,
        "tagged_tokens": tagged_tokens,
        "tag_ratio": round(tagged_tokens / total_tokens, 4) if total_tokens > 0 else 0,
        "entity_type_counts": dict(entity_counts.most_common()),
        "bio_tag_distribution": dict(tag_distribution.most_common()),
        "label_set": NER_LABELS,
        "label_to_id": LABEL_TO_ID,
        "elapsed_seconds": round(elapsed, 1),
    }

    print(f"Writing stats to {stats_path}...", file=sys.stderr)
    with open(stats_path, "w") as f:
        json.dump(stats, f, indent=2)

    # Print summary
    print(f"\n{'='*60}", file=sys.stderr)
    print(f"NER Training Data Generation Complete", file=sys.stderr)
    print(f"{'='*60}", file=sys.stderr)
    print(f"Ground truth records:    {stats['total_ground_truth_records']}", file=sys.stderr)
    print(f"Records with entities:   {stats['records_with_entities']}", file=sys.stderr)
    print(f"Total tokens:            {stats['total_tokens']}", file=sys.stderr)
    print(f"Tagged tokens:           {stats['tagged_tokens']} ({stats['tag_ratio']*100:.1f}%)", file=sys.stderr)
    print(f"Elapsed:                 {elapsed:.1f}s", file=sys.stderr)
    print(f"\nEntity type distribution:", file=sys.stderr)
    for ent_type, count in entity_counts.most_common():
        print(f"  {ent_type:12s}: {count:6d}", file=sys.stderr)
    print(f"\nOutput files:", file=sys.stderr)
    print(f"  BIO:        {bio_path}", file=sys.stderr)
    print(f"  HuggingFace: {hf_path}", file=sys.stderr)
    print(f"  Stats:      {stats_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
