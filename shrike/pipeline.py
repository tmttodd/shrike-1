"""Shrike pipeline — any log format in, OCSF JSON out.

Orchestrates the 5-stage pipeline:
  1. Detector  — regex/heuristic format fingerprinting (<1ms)
  2. Classifier — DistilBERT 65-class OCSF classification (~5ms CPU)
  3. Filter — YAML filter pack evaluation (<1ms)
  4. Extractor — schema-injected LLM field extraction (~500ms CPU)
  5. Validator — OCSF schema compliance check (<1ms)

Usage:
    pipe = ShrikePipeline(
        classifier_model="/path/to/distilbert",
        extractor_api="http://localhost:11434/v1",
    )
    result = pipe.process("Jan  1 12:00:00 host sshd[1234]: Accepted password for user1")
    print(result.event)  # OCSF JSON
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from shrike.detector.format_detector import detect_format, LogFormat
from shrike.filter.filter_engine import FilterEngine, FilterPack, FilterResult
from shrike.validator.ocsf_validator import OCSFValidator, ValidationResult


@dataclass
class PipelineResult:
    """Complete result from the Shrike pipeline."""
    # Input
    raw_log: str
    log_format: LogFormat

    # Classification
    class_uid: int = 0
    class_name: str = ""
    classification_confidence: float = 0.0

    # Filter
    filter_action: str = "keep"  # "keep" or "drop"
    filter_rule: str = ""

    # Extraction
    event: dict[str, Any] = field(default_factory=dict)
    extraction_error: str | None = None

    # Validation
    valid: bool = False
    validation_errors: int = 0
    validation_warnings: int = 0
    field_coverage: float = 0.0

    # Timing
    detect_ms: float = 0.0
    classify_ms: float = 0.0
    filter_ms: float = 0.0
    extract_ms: float = 0.0
    validate_ms: float = 0.0
    total_ms: float = 0.0

    @property
    def dropped(self) -> bool:
        return self.filter_action == "drop"

    def to_dict(self) -> dict[str, Any]:
        """Serialize the result for JSON output."""
        return {
            "event": self.event,
            "metadata": {
                "raw_log": self.raw_log,
                "log_format": self.log_format.value,
                "class_uid": self.class_uid,
                "class_name": self.class_name,
                "classification_confidence": self.classification_confidence,
                "filter_action": self.filter_action,
                "valid": self.valid,
                "field_coverage": round(self.field_coverage, 3),
                "timing_ms": {
                    "detect": round(self.detect_ms, 2),
                    "classify": round(self.classify_ms, 2),
                    "filter": round(self.filter_ms, 2),
                    "extract": round(self.extract_ms, 2),
                    "validate": round(self.validate_ms, 2),
                    "total": round(self.total_ms, 2),
                },
            },
        }


class ShrikePipeline:
    """Main pipeline orchestrator."""

    def __init__(
        self,
        classifier_model: str | Path | None = None,
        classifier_type: str = "distilbert",
        extractor_api: str = "http://localhost:11434/v1",
        extractor_model: str = "shrike-extractor",
        schemas_dir: str | Path | None = None,
        filter_packs_dir: str | Path | None = None,
        active_filter: str | None = None,
        auto_fix: bool = True,
        min_confidence: float = 0.3,
    ):
        """Initialize the pipeline.

        Args:
            classifier_model: Path to DistilBERT model dir or embedding exemplars.
            classifier_type: "distilbert" or "embedding".
            extractor_api: OpenAI-compatible API base URL for the extractor LLM.
            extractor_model: Model name for the extractor API.
            schemas_dir: Path to OCSF schema files.
            filter_packs_dir: Path to filter pack YAML files.
            active_filter: Name of the filter pack to activate.
            auto_fix: If True, apply validator suggested fixes automatically.
            min_confidence: Minimum classification confidence to proceed with extraction.
        """
        # Resolve paths
        base_dir = Path(__file__).parent.parent
        if schemas_dir is None:
            schemas_dir = base_dir / "schemas" / "ocsf_v1.3" / "classes"
        else:
            schemas_dir = Path(schemas_dir)

        if filter_packs_dir is not None:
            filter_packs_dir = Path(filter_packs_dir)
        else:
            filter_packs_dir = base_dir / "filters"

        self._auto_fix = auto_fix
        self._min_confidence = min_confidence

        # Stage 1: Detector (always available — pure regex)
        # Nothing to initialize

        # Stage 2: Classifier
        self._classifier = None
        if classifier_model is not None:
            classifier_model = Path(classifier_model)
            if classifier_type == "distilbert":
                from shrike.classifier.ocsf_classifier import DistilBERTClassifier
                self._classifier = DistilBERTClassifier(classifier_model, schemas_dir)
            elif classifier_type == "embedding":
                from shrike.classifier.ocsf_classifier import EmbeddingClassifier
                self._classifier = EmbeddingClassifier(
                    exemplars_path=classifier_model, schemas_dir=schemas_dir
                )

        # Stage 3: Filter
        self._filter_engine = FilterEngine(filter_packs_dir)
        if active_filter and active_filter in self._filter_engine.available_packs:
            self._filter_engine.set_active(active_filter)

        # Stage 4: Extractor
        from shrike.extractor.schema_injected_extractor import SchemaInjectedExtractor
        self._extractor = SchemaInjectedExtractor(
            schemas_dir=schemas_dir,
            api_base=extractor_api,
            model=extractor_model,
        )

        # Stage 5: Validator
        self._validator = OCSFValidator(schemas_dir)

    def process(self, raw_log: str) -> PipelineResult:
        """Process a single log line through the full pipeline.

        Args:
            raw_log: The raw log line to normalize.

        Returns:
            PipelineResult with the extracted and validated OCSF event.
        """
        pipeline_start = time.monotonic()
        result = PipelineResult(raw_log=raw_log, log_format=LogFormat.CUSTOM)

        # Stage 1: Detect format
        t0 = time.monotonic()
        result.log_format = detect_format(raw_log)
        result.detect_ms = (time.monotonic() - t0) * 1000

        # Stage 2: Classify
        t0 = time.monotonic()
        if self._classifier is not None:
            classification = self._classifier.classify(raw_log)
            result.class_uid = classification.class_uid
            result.class_name = classification.class_name
            result.classification_confidence = classification.confidence
        else:
            # No classifier — pass through with class 0 (Base Event)
            result.class_uid = 0
            result.class_name = "Base Event"
            result.classification_confidence = 0.0
        result.classify_ms = (time.monotonic() - t0) * 1000

        # Confidence gate
        if result.classification_confidence < self._min_confidence and self._classifier is not None:
            result.class_uid = 0
            result.class_name = "Base Event (low confidence)"

        # Stage 3: Filter
        t0 = time.monotonic()
        filter_result = self._filter_engine.evaluate(
            class_uid=result.class_uid,
            severity_id=1,  # Default until extraction
            confidence=result.classification_confidence,
        )
        result.filter_action = filter_result.action
        result.filter_rule = filter_result.rule_description
        result.filter_ms = (time.monotonic() - t0) * 1000

        # Short-circuit if filtered out
        if result.dropped:
            result.total_ms = (time.monotonic() - pipeline_start) * 1000
            return result

        # Stage 4: Extract
        t0 = time.monotonic()
        extraction = self._extractor.extract(
            raw_log=raw_log,
            class_uid=result.class_uid,
            class_name=result.class_name,
        )
        result.event = extraction.event
        result.extraction_error = extraction.error
        result.extract_ms = (time.monotonic() - t0) * 1000

        # Stage 5: Validate
        t0 = time.monotonic()
        validation = self._validator.validate(result.event, class_uid=result.class_uid)
        result.valid = validation.valid
        result.validation_errors = validation.error_count
        result.validation_warnings = validation.warning_count
        result.field_coverage = validation.field_coverage

        # Auto-fix if enabled
        if self._auto_fix and not validation.valid:
            fixed = self._validator.suggest_fixes(result.event, validation)
            # Re-validate after fix
            revalidation = self._validator.validate(fixed, class_uid=result.class_uid)
            if revalidation.valid or revalidation.error_count < validation.error_count:
                result.event = fixed
                result.valid = revalidation.valid
                result.validation_errors = revalidation.error_count
                result.validation_warnings = revalidation.warning_count
                result.field_coverage = revalidation.field_coverage

        result.validate_ms = (time.monotonic() - t0) * 1000
        result.total_ms = (time.monotonic() - pipeline_start) * 1000

        return result

    def process_batch(
        self,
        logs: list[str],
        progress_callback: Any = None,
    ) -> list[PipelineResult]:
        """Process a batch of log lines.

        Args:
            logs: List of raw log lines.
            progress_callback: Optional callable(index, total, result) for progress.

        Returns:
            List of PipelineResults.
        """
        results = []
        for i, log in enumerate(logs):
            result = self.process(log)
            results.append(result)
            if progress_callback:
                progress_callback(i, len(logs), result)
        return results

    @property
    def available_filters(self) -> list[str]:
        return self._filter_engine.available_packs

    @property
    def known_classes(self) -> list[int]:
        return self._validator.known_classes
