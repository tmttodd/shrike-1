"""NER-based entity extractor — Tier 1.5 in the extraction pipeline.

Uses a fine-tuned SecureBERT 2.0 token classifier to extract security
entities (IP, port, user, hostname, process, etc.) from raw log text.

Sits between Tier 1 (patterns) and Tier 2 (LLM):
  - Tier 1 (patterns): regex, deterministic, <1ms — handles known formats
  - Tier 1.5 (NER): ML token classifier, ~10-50ms — handles freetext
  - Tier 2 (LLM): full language model, ~200ms — handles unknown formats

The NER model was fine-tuned on 10,324 labeled log lines with 15 entity
types. F1: 0.858 on held-out validation set.

Usage:
    extractor = NERExtractor("models/shrike-ner")
    result = extractor.extract("Mar 29 10:00:00 host sshd[1234]: Accepted password for admin from 192.168.1.100 port 22")
    # result = {"user": "admin", "src_endpoint.ip": "192.168.1.100", "src_endpoint.port": 22, ...}
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


# Entity type → OCSF field path mapping
# Maps NER BIO labels to OCSF fields
ENTITY_OCSF_MAP: dict[str, str] = {
    "IP": "src_endpoint.ip",       # First IP = source (heuristic)
    "PORT": "src_endpoint.port",   # First port = source
    "USER": "user",
    "HOSTNAME": "device.hostname",
    "PROCESS": "process.name",
    "PID": "process.pid",
    "PATH": "process.file.path",
    "TIMESTAMP": "time",
    "PROTOCOL": "connection_info.protocol_name",
    "ACTION": "activity_name",
    "STATUS": "status",
    "FINDING": "finding_info.title",
    "SID": "finding_info.uid",
    "MAC": "device.mac",
    "EMAIL": "user",
}

# For second occurrence of IP/PORT, map to destination
ENTITY_OCSF_MAP_SECOND: dict[str, str] = {
    "IP": "dst_endpoint.ip",
    "PORT": "dst_endpoint.port",
}


class NERExtractor:
    """Token classification NER extractor using fine-tuned SecureBERT 2.0."""

    def __init__(self, model_path: str | Path = "models/shrike-ner"):
        self._model_path = Path(model_path)
        self._pipeline = None
        self._label_map: dict[int, str] = {}
        self._loaded = False

    def _lazy_load(self) -> bool:
        """Lazy-load the model on first use."""
        if self._loaded:
            return self._pipeline is not None

        self._loaded = True
        try:
            from transformers import AutoModelForTokenClassification, AutoTokenizer, pipeline

            if not self._model_path.exists():
                return False

            # Load label map
            label_map_path = self._model_path / "label_map.json"
            if label_map_path.exists():
                data = json.load(open(label_map_path))
                self._label_map = {int(k): v for k, v in data.get("id2label", {}).items()}

            tokenizer = AutoTokenizer.from_pretrained(str(self._model_path))
            model = AutoModelForTokenClassification.from_pretrained(str(self._model_path))

            self._pipeline = pipeline(
                "ner",
                model=model,
                tokenizer=tokenizer,
                aggregation_strategy="first",  # Merge subword tokens by first token's label
                device=-1,  # CPU (fast enough for 150M model)
            )
            return True
        except Exception:
            return False

    def extract(
        self,
        raw_log: str,
        class_uid: int = 0,
        class_name: str = "",
    ) -> dict[str, Any] | None:
        """Extract entities from a raw log line using the NER model.

        Returns dict of {ocsf_field: value} or None if model unavailable
        or too few entities found.
        """
        if not self._lazy_load():
            return None

        start = time.monotonic()

        # Truncate very long logs (model max is 512 tokens)
        text = raw_log[:1024]

        try:
            entities = self._pipeline(text)
        except Exception:
            return None

        if not entities:
            return None

        # Map entities to OCSF fields
        fields: dict[str, Any] = {}
        confidence: dict[str, str] = {}
        entity_counts: dict[str, int] = {}  # Track occurrences per entity type

        for ent in entities:
            entity_type = ent["entity_group"]
            value = ent["word"].strip()
            score = ent["score"]

            # Skip low-confidence entities (0.7 threshold — higher than default
            # because NER on log text has more noise than natural language)
            if score < 0.7:
                continue

            # Skip empty/whitespace values
            if not value or value in ("#", "##"):
                continue

            # Clean up tokenizer artifacts
            value = value.replace(" ##", "").replace("##", "").strip()
            if not value or len(value) < 2:
                continue

            # Validate entity-specific formats
            if entity_type == "IP":
                import ipaddress as _ipa
                try:
                    _ipa.ip_address(value.strip("[]"))
                except ValueError:
                    continue  # Not a valid IP — skip

            # Track occurrence count for positional disambiguation
            entity_counts[entity_type] = entity_counts.get(entity_type, 0) + 1
            count = entity_counts[entity_type]

            # Map to OCSF field
            if count == 1:
                ocsf_path = ENTITY_OCSF_MAP.get(entity_type)
            elif count == 2:
                ocsf_path = ENTITY_OCSF_MAP_SECOND.get(
                    entity_type, ENTITY_OCSF_MAP.get(entity_type))
            else:
                continue  # Skip 3rd+ occurrence

            if not ocsf_path:
                continue

            # Don't overwrite existing fields
            if ocsf_path in fields:
                continue

            # Type coercion
            if entity_type == "PORT":
                try:
                    value = int(value)
                    if not (0 < value <= 65535):
                        continue
                except (ValueError, TypeError):
                    continue
            elif entity_type == "PID":
                try:
                    value = int(value)
                except (ValueError, TypeError):
                    continue

            fields[ocsf_path] = value
            confidence[ocsf_path] = "ner"

        # Only return if we found enough entities
        if len(fields) < 2:
            return None

        elapsed_ms = (time.monotonic() - start) * 1000

        return {
            "fields": fields,
            "confidence": confidence,
            "entity_count": len(fields),
            "elapsed_ms": elapsed_ms,
        }

    @property
    def available(self) -> bool:
        """Check if the NER model is available."""
        return self._model_path.exists() and (self._model_path / "model.safetensors").exists()

    @property
    def model_info(self) -> dict[str, Any]:
        """Model metadata."""
        return {
            "path": str(self._model_path),
            "available": self.available,
            "labels": len(self._label_map),
            "loaded": self._pipeline is not None,
        }
