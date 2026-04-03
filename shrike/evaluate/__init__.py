"""Shrike multi-dimensional evaluation framework.

Measures extraction quality across 8 dimensions:
  1. Breadth (field count)
  2. Accuracy (value correctness)
  3. Schema Compliance (required fields)
  4. Relationship Integrity (entity pairing)
  5. Ground Truth Quality (label errors)
  6. Cache Quality (template precision)
  7. Type Fidelity (IP/port/timestamp format)
  8. Observables (OCSF observables[] completeness)
"""

from shrike.evaluate.types import (
    DimensionScore, EvaluationReport, FailureDetail,
    get_nested, set_nested, walk_event,
)
from shrike.evaluate.hallucination import HallucinationChecker
from shrike.evaluate.coercion import OCSFCoercer
from shrike.evaluate.observables import ObservablesBuilder

__all__ = [
    "DimensionScore", "EvaluationReport", "FailureDetail",
    "HallucinationChecker", "OCSFCoercer", "ObservablesBuilder",
    "get_nested", "set_nested", "walk_event",
]
