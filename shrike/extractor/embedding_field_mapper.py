"""Embedding-based OCSF field name mapper.

Uses sentence-transformers with all-MiniLM-L6-v2 (22MB) to map unseen vendor
field names to OCSF paths via cosine similarity against a pre-computed index
of known field aliases.

This is Strategy 3 in the field mapping pipeline (after exact alias lookup
and fuzzy substring rules).

Requires: pip install shrike[embedding]
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import numpy as np

logger = logging.getLogger(__name__)

# Lazy import — sentence-transformers is optional
_SentenceTransformer = None


def _get_sentence_transformer():
    """Lazy-load SentenceTransformer class."""
    global _SentenceTransformer
    if _SentenceTransformer is None:
        from sentence_transformers import SentenceTransformer
        _SentenceTransformer = SentenceTransformer
    return _SentenceTransformer


def _normalize_field_name(field: str) -> str:
    """Convert a field name into a more embedding-friendly string.

    Examples:
        "sourceAddress" -> "source address"
        "src_endpoint.ip" -> "src endpoint ip"
        "callerIpAddress" -> "caller ip address"
        "SHA256HashData" -> "sha256 hash data"
    """
    import re
    # Replace dots, underscores, hyphens with spaces
    s = field.replace(".", " ").replace("_", " ").replace("-", " ")
    # Split camelCase: insert space before uppercase letters preceded by lowercase
    s = re.sub(r"([a-z])([A-Z])", r"\1 \2", s)
    # Split on transitions from uppercase sequences to lowercase (e.g., SHA256Hash -> SHA256 Hash)
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", s)
    return s.lower().strip()


# Synthetic aliases to augment the training data. These cover common vendor
# patterns that the 110-entry alias table doesn't include, improving recall
# for field names like "logTimestamp", "targetUser", "parentProcessId", etc.
_AUGMENTED_ALIASES: dict[str, str] = {
    "timestamp": "time",
    "log_timestamp": "time",
    "event_time": "time",
    "event_timestamp": "time",
    "log_time": "time",
    "created_time": "time",
    "recorded_at": "time",
    "occurred_at": "time",
    "target_user": "user",
    "target_username": "user",
    "target_user_name": "user",
    "dest_user": "user",
    "account_name": "user",
    "subject_user_name": "user",
    "parent_process_id": "process.parent_process.pid",
    "parent_pid": "process.parent_process.pid",
    "ppid": "process.parent_process.pid",
    "parent_process_pid": "process.parent_process.pid",
    "source_hostname": "device.hostname",
    "target_hostname": "device.hostname",
    "dest_hostname": "device.hostname",
    "event_severity": "severity",
    "alert_severity": "severity",
    "risk_score": "severity",
    "threat_severity": "severity",
    "url_path": "http_request.url.path",
    "request_path": "http_request.url.path",
    "response_status": "http_response.code",
    "http_status": "http_response.code",
    "alert_name": "finding_info.title",
    "threat_name": "finding_info.title",
    "detection_name": "finding_info.title",
    "signature": "finding_info.title",
    "rule_name": "finding_info.title",
}


class EmbeddingFieldMapper:
    """Maps vendor field names to OCSF paths using embedding similarity.

    Uses all-MiniLM-L6-v2 to embed field names and finds the closest known
    alias via cosine similarity.

    Usage:
        mapper = EmbeddingFieldMapper()
        ocsf_path, score = mapper.map_field("sourceAddress")
        # ("src_endpoint.ip", 0.87)
    """

    DEFAULT_MODEL = "all-MiniLM-L6-v2"
    DEFAULT_THRESHOLD = 0.6

    def __init__(
        self,
        aliases_path: Path | None = None,
        index_path: Path | None = None,
        model_name: str = DEFAULT_MODEL,
        threshold: float = DEFAULT_THRESHOLD,
    ):
        self._model_name = model_name
        self._threshold = threshold
        self._model = None  # Lazy-loaded

        data_dir = Path(__file__).parent.parent.parent / "data"
        self._aliases_path = aliases_path or data_dir / "field_aliases.json"
        self._index_path = index_path or data_dir / "field_embeddings.npz"

        # Populated by _ensure_index()
        self._field_names: list[str] = []
        self._ocsf_paths: list[str] = []
        self._embeddings: np.ndarray | None = None
        self._index_loaded = False

    def _ensure_model(self):
        """Lazy-load the sentence-transformer model."""
        if self._model is None:
            SentenceTransformer = _get_sentence_transformer()
            self._model = SentenceTransformer(self._model_name, device="cpu")
        return self._model

    def _ensure_index(self):
        """Load the pre-computed index from disk, or build it on the fly."""
        if self._index_loaded:
            return

        if self._index_path.exists():
            self._load_index(self._index_path)
        else:
            logger.info("No pre-computed index found at %s, building on the fly", self._index_path)
            self._build_from_aliases()

        self._index_loaded = True

    def _load_index(self, path: Path):
        """Load pre-computed embeddings from .npz file."""
        data = np.load(path, allow_pickle=True)
        self._embeddings = data["embeddings"].astype(np.float32)
        self._field_names = data["field_names"].tolist()
        self._ocsf_paths = data["ocsf_paths"].tolist()
        logger.info(
            "Loaded embedding index: %d entries from %s",
            len(self._field_names), path,
        )

    @staticmethod
    def _merge_aliases(aliases: dict[str, str]) -> dict[str, str]:
        """Merge base aliases with augmented synthetic aliases."""
        merged = dict(aliases)
        for field, ocsf_path in _AUGMENTED_ALIASES.items():
            if field not in merged:
                merged[field] = ocsf_path
        return merged

    def _build_from_aliases(self):
        """Build index from the aliases JSON file plus augmented aliases."""
        if not self._aliases_path.exists():
            raise FileNotFoundError(f"Aliases file not found: {self._aliases_path}")

        with open(self._aliases_path) as f:
            aliases: dict[str, str] = json.load(f)

        merged = self._merge_aliases(aliases)
        self._field_names = list(merged.keys())
        self._ocsf_paths = list(merged.values())

        # Normalize field names for better embedding quality
        normalized = [_normalize_field_name(fn) for fn in self._field_names]

        model = self._ensure_model()
        self._embeddings = model.encode(
            normalized,
            show_progress_bar=False,
            normalize_embeddings=True,
        ).astype(np.float32)

    def build_index(self, save_path: Path | None = None) -> Path:
        """Build and save the embedding index to disk.

        Args:
            save_path: Where to save the .npz file. Defaults to data/field_embeddings.npz.

        Returns:
            Path to the saved index file.
        """
        save_path = save_path or self._index_path

        if not self._aliases_path.exists():
            raise FileNotFoundError(f"Aliases file not found: {self._aliases_path}")

        with open(self._aliases_path) as f:
            aliases: dict[str, str] = json.load(f)

        merged = self._merge_aliases(aliases)
        field_names = list(merged.keys())
        ocsf_paths = list(merged.values())
        normalized = [_normalize_field_name(fn) for fn in field_names]

        model = self._ensure_model()
        embeddings = model.encode(
            normalized,
            show_progress_bar=True,
            normalize_embeddings=True,
        ).astype(np.float32)

        np.savez_compressed(
            save_path,
            embeddings=embeddings,
            field_names=np.array(field_names, dtype=object),
            ocsf_paths=np.array(ocsf_paths, dtype=object),
        )

        # Update internal state
        self._field_names = field_names
        self._ocsf_paths = ocsf_paths
        self._embeddings = embeddings
        self._index_loaded = True

        size_kb = save_path.stat().st_size / 1024
        logger.info("Saved embedding index: %d entries, %.1f KB -> %s", len(field_names), size_kb, save_path)
        return save_path

    def map_field(self, vendor_field: str) -> tuple[str | None, float]:
        """Map a vendor field name to an OCSF path using embedding similarity.

        Args:
            vendor_field: The vendor-specific field name (e.g., "sourceAddress").

        Returns:
            Tuple of (ocsf_path, similarity_score). Returns (None, 0.0) if
            no match above threshold.
        """
        self._ensure_index()

        if self._embeddings is None or len(self._field_names) == 0:
            return None, 0.0

        model = self._ensure_model()
        normalized = _normalize_field_name(vendor_field)
        query_embedding = model.encode(
            [normalized],
            show_progress_bar=False,
            normalize_embeddings=True,
        ).astype(np.float32)

        # Cosine similarity (embeddings are already L2-normalized)
        similarities = (self._embeddings @ query_embedding.T).squeeze()

        best_idx = int(np.argmax(similarities))
        best_score = float(similarities[best_idx])

        if best_score >= self._threshold:
            return self._ocsf_paths[best_idx], best_score

        return None, best_score

    def map_field_topk(self, vendor_field: str, k: int = 5) -> list[tuple[str, str, float]]:
        """Return top-k matches for debugging and analysis.

        Returns:
            List of (known_field_name, ocsf_path, similarity_score) tuples,
            sorted by descending similarity.
        """
        self._ensure_index()

        if self._embeddings is None or len(self._field_names) == 0:
            return []

        model = self._ensure_model()
        normalized = _normalize_field_name(vendor_field)
        query_embedding = model.encode(
            [normalized],
            show_progress_bar=False,
            normalize_embeddings=True,
        ).astype(np.float32)

        similarities = (self._embeddings @ query_embedding.T).squeeze()
        top_indices = np.argsort(similarities)[::-1][:k]

        return [
            (self._field_names[i], self._ocsf_paths[i], float(similarities[i]))
            for i in top_indices
        ]

    @property
    def entry_count(self) -> int:
        """Number of entries in the index."""
        self._ensure_index()
        return len(self._field_names)

    @property
    def unique_ocsf_paths(self) -> int:
        """Number of unique OCSF output classes."""
        self._ensure_index()
        return len(set(self._ocsf_paths))
