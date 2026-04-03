"""Core data types for the Shrike evaluation framework.

These dataclasses flow through all 8 dimensions and the CLI report.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class FailureDetail:
    """A single identified failure within a dimension."""
    description: str        # Human-readable: "user field wrong in 12 logs"
    count: int              # How many logs affected
    examples: list[str] = field(default_factory=list)  # Up to 3 raw_log snippets
    field: str = ""         # OCSF field involved, if applicable
    category: str = ""      # Root cause category for feedback routing

    def to_dict(self) -> dict[str, Any]:
        return {
            "description": self.description,
            "count": self.count,
            "field": self.field,
            "category": self.category,
            "examples": self.examples[:3],
        }


@dataclass
class DimensionScore:
    """Score for one evaluation dimension."""
    name: str               # "accuracy", "schema_compliance", etc.
    score: float            # 0.0 to 100.0
    total: int              # Number of items evaluated
    passed: int             # Number that passed
    failures: list[FailureDetail] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        sorted_failures = sorted(self.failures, key=lambda x: -x.count)
        return {
            "name": self.name,
            "score": round(self.score, 1),
            "total": self.total,
            "passed": self.passed,
            "top_failures": [f.to_dict() for f in sorted_failures[:10]],
            **self.metadata,
        }


# Weighted composite — accuracy and type_fidelity matter most
DIMENSION_WEIGHTS: dict[str, float] = {
    "breadth": 0.12,
    "accuracy": 0.20,
    "schema_compliance": 0.12,
    "relationship_integrity": 0.08,
    "ground_truth_quality": 0.05,
    "cache_quality": 0.03,
    "type_fidelity": 0.12,
    "observables": 0.08,
    "attack_coverage": 0.20,       # Forward direction — the "so what" of normalization
}


@dataclass
class EvaluationReport:
    """Complete evaluation across all dimensions."""
    version: str = "1.0.0"
    mode: str = "pattern"   # "pattern" or "tiered"
    dimensions: dict[str, DimensionScore] = field(default_factory=dict)
    elapsed_seconds: float = 0.0
    test_size: int = 0
    golden_size: int = 0
    canary_size: int = 0

    @property
    def composite_score(self) -> float:
        """Weighted composite across all measured dimensions."""
        total_weight = 0.0
        weighted_sum = 0.0
        for name, dim in self.dimensions.items():
            w = DIMENSION_WEIGHTS.get(name, 0.1)
            weighted_sum += dim.score * w
            total_weight += w
        return weighted_sum / total_weight if total_weight > 0 else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "mode": self.mode,
            "composite_score": round(self.composite_score, 1),
            "test_size": self.test_size,
            "golden_size": self.golden_size,
            "canary_size": self.canary_size,
            "elapsed_seconds": round(self.elapsed_seconds, 2),
            "dimensions": {k: v.to_dict() for k, v in self.dimensions.items()},
        }


# --- Utility: nested dict traversal (shared across dimensions + golden tests) ---

def get_nested(obj: dict, dotted_path: str) -> Any:
    """Traverse a nested dict using dotted path notation.

    get_nested({"src_endpoint": {"ip": "1.2.3.4"}}, "src_endpoint.ip")
    → "1.2.3.4"
    """
    parts = dotted_path.split(".")
    current = obj
    for part in parts:
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def set_nested(obj: dict, dotted_path: str, value: Any) -> None:
    """Set a value in a nested dict using dotted path notation."""
    parts = dotted_path.split(".")
    current = obj
    for part in parts[:-1]:
        if part not in current or not isinstance(current[part], dict):
            current[part] = {}
        current = current[part]
    current[parts[-1]] = value


def walk_event(event: dict, prefix: str = "") -> list[tuple[str, Any]]:
    """Flatten a nested event dict into (dotted_path, value) pairs.

    walk_event({"src_endpoint": {"ip": "1.2.3.4", "port": 22}})
    → [("src_endpoint.ip", "1.2.3.4"), ("src_endpoint.port", 22)]
    """
    pairs: list[tuple[str, Any]] = []
    for k, v in event.items():
        full_path = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            pairs.extend(walk_event(v, full_path))
        else:
            pairs.append((full_path, v))
    return pairs
