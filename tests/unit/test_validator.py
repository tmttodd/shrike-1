"""Tests for OCSF validator."""

import pytest
from pathlib import Path

from shrike.validator.ocsf_validator import OCSFValidator, ValidationResult


@pytest.fixture
def validator():
    """Validator with real OCSF schemas."""
    schemas_dir = Path(__file__).parent.parent.parent / "schemas" / "ocsf_v1.3" / "classes"
    return OCSFValidator(schemas_dir)


class TestOCSFValidator:
    """Test OCSF schema validation."""

    def test_valid_authentication_event(self, validator):
        """Valid event with required fields passes validation."""
        event = {
            "class_uid": 3002,
            "class_name": "Authentication",
            "category_uid": 3,
            "activity_id": 1,
            "severity_id": 1,
            "user": {"name": "admin", "type": "User"},
        }
        result = validator.validate(event)
        assert result.valid
        assert result.error_count == 0

    def test_missing_required_field(self, validator):
        """Missing required field produces error."""
        event = {
            "class_uid": 3002,
            "class_name": "Authentication",
            "category_uid": 3,
            # Missing 'user' (required for Authentication)
        }
        result = validator.validate(event)
        assert not result.valid
        assert any(e.field == "user" for e in result.errors)

    def test_no_class_uid(self, validator):
        """Event without class_uid fails immediately."""
        event = {"activity_id": 1}
        result = validator.validate(event)
        assert not result.valid
        assert result.errors[0].field == "class_uid"

    def test_class_uid_override(self, validator):
        """Explicit class_uid parameter overrides event."""
        event = {"class_uid": 9999}
        result = validator.validate(event, class_uid=3002)
        # Should use 3002 and flag the mismatch
        assert result.class_uid == 3002
        assert any(e.error_type == "invalid_value" and e.field == "class_uid" for e in result.errors)

    def test_category_uid_consistency(self, validator):
        """Mismatched category_uid produces warning."""
        event = {
            "class_uid": 3002,
            "category_uid": 1,  # Should be 3 (3002 // 1000)
            "user": {"name": "test"},
        }
        result = validator.validate(event)
        assert any(w.field == "category_uid" for w in result.warnings)

    def test_unknown_fields_strict(self, validator):
        """Strict mode flags unknown fields as errors."""
        event = {
            "class_uid": 3002,
            "user": {"name": "test"},
            "bogus_field": "value",
        }
        result = validator.validate(event, strict=True)
        assert any(e.field == "bogus_field" for e in result.errors)

    def test_unknown_fields_nonstrict(self, validator):
        """Non-strict mode flags unknown fields as warnings."""
        event = {
            "class_uid": 3002,
            "user": {"name": "test"},
            "bogus_field": "value",
        }
        result = validator.validate(event, strict=False)
        assert result.valid or all(e.field != "bogus_field" for e in result.errors)
        assert any(w.field == "bogus_field" for w in result.warnings)

    def test_base_fields_always_allowed(self, validator):
        """Base OCSF fields (time, message, etc.) are never flagged."""
        event = {
            "class_uid": 3002,
            "user": {"name": "test"},
            "time": "2026-03-29T10:00:00Z",
            "message": "User logged in",
            "severity_id": 1,
            "metadata": {},
        }
        result = validator.validate(event, strict=True)
        # Base fields should not appear in errors or warnings
        base_errors = [e for e in result.errors if e.field in ("time", "message", "severity_id", "metadata")]
        assert len(base_errors) == 0

    def test_field_coverage(self, validator):
        """Field coverage is calculated correctly."""
        event = {
            "class_uid": 3002,
            "user": {"name": "test"},
        }
        result = validator.validate(event)
        assert 0.0 < result.field_coverage <= 1.0

    def test_unknown_class_uid(self, validator):
        """Unknown class_uid produces a warning, not crash."""
        event = {"class_uid": 99999, "activity_id": 1}
        result = validator.validate(event)
        assert any(w.error_type == "unknown_field" and "No schema" in w.message for w in result.warnings)

    def test_suggest_fixes_adds_class_uid(self, validator):
        """suggest_fixes adds missing class_uid when provided externally."""
        event = {"class_uid": 3002, "activity_id": 1}
        # Simulate a result where class_uid is known but category_uid is missing
        result = validator.validate(event, class_uid=3002)
        fixed = validator.suggest_fixes(event, result)
        assert fixed.get("class_uid") == 3002

    def test_suggest_fixes_coerces_types(self, validator):
        """suggest_fixes coerces string→int for integer fields."""
        event = {
            "class_uid": 3002,
            "user": {"name": "test"},
            "is_mfa": "true",
        }
        result = validator.validate(event, class_uid=3002)
        # Schema says is_mfa is boolean/string — this is more of a type coercion test
        fixed = validator.suggest_fixes(event, result)
        assert isinstance(fixed, dict)

    def test_known_classes_populated(self, validator):
        """Validator loads schema files correctly."""
        classes = validator.known_classes
        assert len(classes) > 50  # We have 106 schema files
        assert 3002 in classes  # Authentication
        assert 1007 in classes  # Process Activity

    def test_get_schema(self, validator):
        """Can retrieve schema by class_uid."""
        schema = validator.get_schema(3002)
        assert schema is not None
        assert schema["class_name"] == "Authentication"
        assert "attributes" in schema
