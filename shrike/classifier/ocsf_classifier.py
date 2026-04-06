"""OCSF class classification via fine-tuned DistilBERT.

Takes a raw log line (already format-detected) and returns the OCSF class UID
with confidence score. This is Stage 2 of the Shrike pipeline — runs in ~5ms on CPU.

Supports two backends:
  - DistilBERT: Fine-tuned 66M param classifier (primary, ~5ms)
  - Embedding KNN: Sentence-transformer similarity (fallback, ~20ms)
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np


@dataclass
class ClassificationResult:
    """Result of OCSF classification."""
    class_uid: int
    class_name: str
    confidence: float
    category_uid: int
    top_k: list[tuple[int, str, float]] | None = None  # [(uid, name, score), ...]


# OCSF v1.3 class UID → name mapping (used by all backends)
OCSF_CLASS_MAP: dict[int, str] = {}

def _load_class_map(schemas_dir: Path) -> dict[int, str]:
    """Load class UID → name mapping from schema files."""
    mapping = {}
    if not schemas_dir.exists():
        return mapping
    for f in schemas_dir.glob("class_*.json"):
        try:
            with open(f) as fh:
                schema = json.load(fh)
            mapping[schema["class_uid"]] = schema["class_name"]
        except Exception as e:
            logger.warning(f"Failed to load schema {f.name}: {e}")
    return mapping


class DistilBERTClassifier:
    """Fine-tuned DistilBERT for 65-class OCSF classification."""

    def __init__(self, model_path: Path, schemas_dir: Path | None = None):
        """Load the fine-tuned model.

        Args:
            model_path: Path to the saved model directory (contains model files + label mapping).
            schemas_dir: Path to OCSF schema files for class name resolution.
        """
        self._model = None
        self._tokenizer = None
        self._label_map: dict[int, int] = {}  # model label index → class_uid
        self._class_map: dict[int, str] = {}

        if schemas_dir is None:
            schemas_dir = Path(__file__).parent.parent.parent / "schemas" / "ocsf_v1.3" / "classes"
        self._class_map = _load_class_map(schemas_dir)

        self._load_model(model_path)

    def _load_model(self, model_path: Path) -> None:
        """Load the DistilBERT model and tokenizer."""
        try:
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
            import torch

            self._tokenizer = AutoTokenizer.from_pretrained(str(model_path))
            self._model = AutoModelForSequenceClassification.from_pretrained(str(model_path))
            self._model.eval()

            # Load label mapping (model index → class_uid)
            label_map_path = model_path / "label_map.json"
            if label_map_path.exists():
                with open(label_map_path) as f:
                    raw = json.load(f)
                # JSON keys are strings, convert to int→int
                self._label_map = {int(k): int(v) for k, v in raw.items()}
            else:
                # Fallback: assume model labels are class_uids directly
                config = self._model.config
                num_labels = config.num_labels
                self._label_map = {i: i for i in range(num_labels)}

        except ImportError:
            raise ImportError(
                "DistilBERT classifier requires: pip install transformers torch"
            )

    def classify(
        self,
        raw_log: str,
        top_k: int = 3,
    ) -> ClassificationResult:
        """Classify a raw log line.

        Args:
            raw_log: The raw log text (up to 512 tokens).
            top_k: Number of top predictions to include.

        Returns:
            ClassificationResult with class_uid, confidence, and top_k alternatives.
        """
        import torch

        # Tokenize
        inputs = self._tokenizer(
            raw_log,
            return_tensors="pt",
            truncation=True,
            max_length=512,
            padding=True,
        )

        # Inference
        with torch.no_grad():
            outputs = self._model(**inputs)
            logits = outputs.logits[0]
            probs = torch.softmax(logits, dim=-1)

        # Get top-k predictions
        top_k_values, top_k_indices = torch.topk(probs, min(top_k, len(probs)))

        results = []
        for score, idx in zip(top_k_values.tolist(), top_k_indices.tolist()):
            class_uid = self._label_map.get(idx, idx)
            class_name = self._class_map.get(class_uid, f"Unknown ({class_uid})")
            results.append((class_uid, class_name, score))

        best_uid, best_name, best_score = results[0]

        return ClassificationResult(
            class_uid=best_uid,
            class_name=best_name,
            confidence=best_score,
            category_uid=best_uid // 1000,
            top_k=results,
        )


class EmbeddingClassifier:
    """Embedding-based KNN classifier (fallback/lightweight).

    Uses sentence-transformers to embed log lines and compare against
    pre-computed class exemplar embeddings.
    """

    def __init__(
        self,
        model_name: str = "all-MiniLM-L6-v2",
        exemplars_path: Path | None = None,
        schemas_dir: Path | None = None,
    ):
        self._model_name = model_name
        self._model = None
        self._exemplar_embeddings: np.ndarray | None = None
        self._exemplar_labels: list[int] = []
        self._class_map: dict[int, str] = {}

        if schemas_dir is None:
            schemas_dir = Path(__file__).parent.parent.parent / "schemas" / "ocsf_v1.3" / "classes"
        self._class_map = _load_class_map(schemas_dir)

        if exemplars_path and exemplars_path.exists():
            self._load_exemplars(exemplars_path)

    def _load_model(self):
        """Lazy-load the sentence transformer model."""
        if self._model is None:
            try:
                from sentence_transformers import SentenceTransformer
                self._model = SentenceTransformer(self._model_name)
            except ImportError:
                raise ImportError(
                    "Embedding classifier requires: pip install sentence-transformers"
                )

    def _load_exemplars(self, path: Path) -> None:
        """Load pre-computed exemplar embeddings."""
        # allow_pickle needed for string label arrays.
        # Only load model files from trusted sources.
        data = np.load(str(path), allow_pickle=True)
        self._exemplar_embeddings = data["embeddings"]
        self._exemplar_labels = data["labels"].tolist()

    def build_exemplars(self, ground_truth_path: Path, output_path: Path) -> None:
        """Build exemplar embeddings from ground truth data.

        Args:
            ground_truth_path: Path to classification_ground_truth.jsonl
            output_path: Where to save the .npz file
        """
        self._load_model()

        texts = []
        labels = []
        with open(ground_truth_path) as f:
            for line in f:
                record = json.loads(line)
                texts.append(record["raw_log"][:512])  # Truncate for embedding
                labels.append(record["class_uid"])

        embeddings = self._model.encode(texts, show_progress_bar=True, batch_size=64)
        np.savez(
            str(output_path),
            embeddings=embeddings,
            labels=np.array(labels),
        )
        self._exemplar_embeddings = embeddings
        self._exemplar_labels = labels

    def classify(
        self,
        raw_log: str,
        top_k: int = 3,
        k_neighbors: int = 5,
    ) -> ClassificationResult:
        """Classify via KNN over exemplar embeddings.

        Args:
            raw_log: The raw log text.
            top_k: Number of top predictions to return.
            k_neighbors: Number of nearest neighbors for voting.
        """
        self._load_model()

        if self._exemplar_embeddings is None:
            raise RuntimeError("No exemplar embeddings loaded. Call build_exemplars() first.")

        # Embed the query
        query_embedding = self._model.encode([raw_log[:512]])[0]

        # Cosine similarity
        similarities = np.dot(self._exemplar_embeddings, query_embedding) / (
            np.linalg.norm(self._exemplar_embeddings, axis=1) * np.linalg.norm(query_embedding)
        )

        # Get top-k_neighbors
        top_indices = np.argsort(similarities)[-k_neighbors:][::-1]

        # Vote by class
        votes: dict[int, float] = {}
        for idx in top_indices:
            label = self._exemplar_labels[idx]
            sim = similarities[idx]
            votes[label] = votes.get(label, 0.0) + sim

        # Sort by total similarity
        sorted_votes = sorted(votes.items(), key=lambda x: -x[1])

        # Normalize confidence
        total = sum(v for _, v in sorted_votes)
        results = []
        for uid, score in sorted_votes[:top_k]:
            name = self._class_map.get(uid, f"Unknown ({uid})")
            results.append((uid, name, score / total if total > 0 else 0.0))

        best_uid, best_name, best_score = results[0]

        return ClassificationResult(
            class_uid=best_uid,
            class_name=best_name,
            confidence=best_score,
            category_uid=best_uid // 1000,
            top_k=results,
        )
