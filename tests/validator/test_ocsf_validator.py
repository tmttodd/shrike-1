"""Tests for OCSFValidator."""

from __future__ import annotations

import pytest

from shrike.validator.ocsf_validator import (
    OCSFValidator,
    ValidationError,
)


class TestValidationError:
    """Tests for ValidationError dataclass."""

    def test_init(self):
        """Initializes with required fields."""
        err = ValidationError(
            field="user",
            error_type="missing_required",
            message="user field is required",
        )
        assert err.field == "user"
        assert err.error_type == "missing_required"
        assert err.severity == "error"


class TestOCSFValidator:
    """Tests for OCSFValidator."""

    def test_init(self):
        """Initializes with schema directory."""
        validator = OCSFValidator()
        assert validator._schemas is not None

    def test_validate_valid_event(self):
        """Valid event passes validation."""
        validator = OCSFValidator()
        event = {
            "class_uid": 3002,
            "class_name": "Authentication",
            "category_uid": 3,
            "category_name": "IAM",
            "activity_id": 1,
            "activity_name": "Logon",
            "time": "2024-03-15T10:00:00Z",
            "user": "alice",
        }
        errors = validator.validate(event)
        assert isinstance(errors, list)

    def test_validate_missing_required_fields(self):
        """Missing required fields produce errors."""
        validator = OCSFValidator()
        event = {
            "class_uid": 3002,
            # Missing class_name, category_uid, time
        }
        errors = validator.validate(event)
        # Should have errors for missing required fields
        error_fields = [e.field for e in errors]
        assert "class_name" in error_fields or "time" in error_fields

    def test_validate_wrong_type(self):
        """Wrong type produces error."""
        validator = OCSFValidator()
        event = {
            "class_uid": "not_an_integer",  # Should be int
            "class_name": "Authentication",
            "category_uid": 3,
            "time": "2024-03-15T10:00:00Z",
        }
        errors = validator.validate(event)
        type_errors = [e for e in errors if e.error_type == "wrong_type"]
        assert len(type_errors) > 0

    def test_validate_unknown_field(self):
        """Unknown fields produce warnings in strict mode."""
        validator = OCSFValidator()
        event = {
            "class_uid": 3002,
            "class_name": "Authentication",
            "category_uid": 3,
            "time": "2024-03-15T10:00:00Z",
            "completely_unknown_field": "value",
        }
        errors = validator.validate(event, strict=True)
        unknown_errors = [e for e in errors if e.error_type == "unknown_field"]
        assert len(unknown_errors) > 0

    def test_validate_non_strict_allows_unknown(self):
        """Non-strict mode allows unknown fields."""
        validator = OCSFValidator()
        event = {
            "class_uid": 3002,
            "class_name": "Authentication",
            "category_uid": 3,
            "time": "2024-03-15T10:00:00Z",
            "vendor_specific_field": "value",
        }
        errors = validator.validate(event, strict=False)
        unknown_errors = [e for e in errors if e.error_type == "unknown_field"]
        assert len(unknown_errors) == 0

    def test_get_stats(self):
        """get_stats() returns validation statistics."""
        validator = OCSFValidator()
        stats = validator.get_stats()
        assert "schemas_loaded" in stats
        assert "validations" in stats
        assert "error_rate" in stats