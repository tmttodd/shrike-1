"""Tests for OCSFCoercer."""

from __future__ import annotations

import pytest

from shrike.evaluate.coercion import (
    OCSFCoercer,
    FIELD_TYPE_MAP,
    SEVERITY_MAP,
    VALID_ACTIVITY_IDS,
)


class TestOCSFCoercer:
    """Tests for OCSFCoercer class."""

    def test_get_type_exact_match(self):
        """get_type returns exact match from FIELD_TYPE_MAP."""
        coercer = OCSFCoercer()
        assert coercer.get_type("src_endpoint.ip") == "ip"
        assert coercer.get_type("src_endpoint.port") == "port"
        assert coercer.get_type("process.pid") == "integer"

    def test_get_type_suffix_based(self):
        """get_type falls back to suffix-based inference."""
        coercer = OCSFCoercer()
        assert coercer.get_type("custom_endpoint.ip") == "ip"
        assert coercer.get_type("custom.port") == "port"
        assert coercer.get_type("custom.pid") == "integer"

    def test_get_type_unknown(self):
        """get_type returns None for unknown fields."""
        coercer = OCSFCoercer()
        assert coercer.get_type("user") is None
        assert coercer.get_type("custom_field") is None

    def test_coerce_ip_valid(self):
        """_coerce_ip returns valid IP addresses."""
        coercer = OCSFCoercer()
        assert coercer._coerce_ip("1.2.3.4") == "1.2.3.4"
        assert coercer._coerce_ip("::1") == "::1"
        assert coercer._coerce_ip("fe80::1") == "fe80::1"

    def test_coerce_ip_strips_port(self):
        """_coerce_ip strips port suffix."""
        coercer = OCSFCoercer()
        assert coercer._coerce_ip("1.2.3.4:22") == "1.2.3.4"
        assert coercer._coerce_ip("192.168.1.1:8080") == "192.168.1.1"

    def test_coerce_ip_strips_brackets(self):
        """_coerce_ip strips bracket notation."""
        coercer = OCSFCoercer()
        assert coercer._coerce_ip("[::1]") == "::1"
        assert coercer._coerce_ip("[fe80::1]") == "fe80::1"

    def test_coerce_ip_invalid(self):
        """_coerce_ip returns None for invalid IPs."""
        coercer = OCSFCoercer()
        assert coercer._coerce_ip("not.an.ip") is None
        assert coercer._coerce_ip("999.999.999.999") is None

    def test_coerce_port_valid(self):
        """_coerce_port returns valid ports."""
        coercer = OCSFCoercer()
        assert coercer._coerce_port(22) == 22
        assert coercer._coerce_port("443") == 443
        assert coercer._coerce_port(8080) == 8080

    def test_coerce_port_with_protocol(self):
        """_coerce_port handles 'port/protocol' format."""
        coercer = OCSFCoercer()
        assert coercer._coerce_port("22/tcp") == 22
        assert coercer._coerce_port("443/https") == 443
        assert coercer._coerce_port("8080/http") == 8080

    def test_coerce_port_out_of_range(self):
        """_coerce_port returns None for out-of-range ports."""
        coercer = OCSFCoercer()
        assert coercer._coerce_port(0) == 0  # Valid
        assert coercer._coerce_port(65535) == 65535  # Valid
        assert coercer._coerce_port(65536) is None
        assert coercer._coerce_port(-1) is None

    def test_coerce_integer_valid(self):
        """_coerce_integer returns valid integers."""
        coercer = OCSFCoercer()
        assert coercer._coerce_integer(123) == 123
        assert coercer._coerce_integer("456") == 456
        assert coercer._coerce_integer(-789) == -789

    def test_coerce_integer_extracts_from_string(self):
        """_coerce_integer extracts numeric from mixed string."""
        coercer = OCSFCoercer()
        assert coercer._coerce_integer("pid=12345") == 12345
        assert coercer._coerce_integer("count42") == 42

    def test_coerce_integer_invalid(self):
        """_coerce_integer returns None for non-numeric strings."""
        coercer = OCSFCoercer()
        assert coercer._coerce_integer("no digits here") is None

    def test_coerce_float_valid(self):
        """_coerce_float returns valid floats."""
        coercer = OCSFCoercer()
        assert coercer._coerce_float(1.5) == 1.5
        assert coercer._coerce_float("2.5") == 2.5
        assert coercer._coerce_float(100) == 100.0

    def test_coerce_float_strips_percent(self):
        """_coerce_float strips percentage sign."""
        coercer = OCSFCoercer()
        assert coercer._coerce_float("50%") == 50.0
        assert coercer._coerce_float("99.5%") == 99.5

    def test_coerce_timestamp_epoch_seconds(self):
        """_coerce_timestamp handles epoch seconds."""
        coercer = OCSFCoercer()
        # 2024-01-01 in seconds
        result = coercer._coerce_timestamp(1704067200)
        assert result == 1704067200

    def test_coerce_timestamp_epoch_milliseconds(self):
        """_coerce_timestamp converts epoch milliseconds to seconds."""
        coercer = OCSFCoercer()
        # 2024-01-01 in milliseconds
        result = coercer._coerce_timestamp(1704067200000)
        assert result == 1704067200.0

    def test_coerce_timestamp_iso8601(self):
        """_coerce_timestamp accepts ISO8601 strings."""
        coercer = OCSFCoercer()
        result = coercer._coerce_timestamp("2024-01-01T00:00:00Z")
        assert result == "2024-01-01T00:00:00Z"

    def test_coerce_timestamp_syslog_format(self):
        """_coerce_timestamp accepts syslog BSD format."""
        coercer = OCSFCoercer()
        result = coercer._coerce_timestamp("Mar 29 10:00:00")
        assert result == "Mar 29 10:00:00"

    def test_coerce_mac_valid(self):
        """_coerce_mac returns normalized MAC address."""
        coercer = OCSFCoercer()
        result = coercer._coerce_mac("00:11:22:33:44:55")
        assert result == "00:11:22:33:44:55"
        result = coercer._coerce_mac("00-11-22-33-44-55")
        assert result == "00:11:22:33:44:55"

    def test_coerce_mac_lowercase(self):
        """_coerce_mac normalizes to lowercase."""
        coercer = OCSFCoercer()
        result = coercer._coerce_mac("AA:BB:CC:DD:EE:FF")
        assert result == "aa:bb:cc:dd:ee:ff"

    def test_coerce_mac_invalid(self):
        """_coerce_mac returns None for invalid MACs."""
        coercer = OCSFCoercer()
        assert coercer._coerce_mac("not a mac") is None
        assert coercer._coerce_mac("00:11:22:33:44") is None  # Too short

    def test_coerce_boolean_true(self):
        """_coerce_boolean returns True for truthy values."""
        coercer = OCSFCoercer()
        assert coercer._coerce_boolean(True) is True
        assert coercer._coerce_boolean("yes") is True
        assert coercer._coerce_boolean("1") is True
        assert coercer._coerce_boolean("true") is True
        assert coercer._coerce_boolean("success") is True

    def test_coerce_boolean_false(self):
        """_coerce_boolean returns False for falsy values."""
        coercer = OCSFCoercer()
        assert coercer._coerce_boolean(False) is False
        assert coercer._coerce_boolean("no") is False
        assert coercer._coerce_boolean("0") is False
        assert coercer._coerce_boolean("false") is False
        assert coercer._coerce_boolean("fail") is False

    def test_coerce_boolean_invalid(self):
        """_coerce_boolean returns None for non-boolean strings."""
        coercer = OCSFCoercer()
        assert coercer._coerce_boolean("maybe") is None

    def test_coerce_severity_by_name(self):
        """_coerce_severity maps severity names to IDs."""
        coercer = OCSFCoercer()
        assert coercer._coerce_severity("low") == 2
        assert coercer._coerce_severity("medium") == 3
        assert coercer._coerce_severity("high") == 4
        assert coercer._coerce_severity("critical") == 5

    def test_coerce_severity_by_id(self):
        """_coerce_severity accepts numeric severity IDs."""
        coercer = OCSFCoercer()
        assert coercer._coerce_severity(3) == 3
        assert coercer._coerce_severity("3") == 3

    def test_coerce_severity_invalid(self):
        """_coerce_severity returns None for invalid values."""
        coercer = OCSFCoercer()
        assert coercer._coerce_severity(100) is None
        assert coercer._coerce_severity("invalid") is None

    def test_coerce_activity_valid(self):
        """_coerce_activity returns valid activity IDs."""
        coercer = OCSFCoercer()
        assert coercer._coerce_activity(1) == 1
        assert coercer._coerce_activity("2") == 2
        assert coercer._coerce_activity(99) == 99

    def test_coerce_activity_invalid(self):
        """_coerce_activity returns None for invalid IDs."""
        coercer = OCSFCoercer()
        assert coercer._coerce_activity(7) is None  # 7 not in VALID_ACTIVITY_IDS
        assert coercer._coerce_activity("invalid") is None

    def test_coerce_generic_strips_quotes(self):
        """_coerce_generic strips quotes from strings."""
        coercer = OCSFCoercer()
        assert coercer._coerce_generic("'value'") == "value"
        assert coercer._coerce_generic('"value"') == "value"
        assert coercer._coerce_generic(123) == 123

    def test_coerce_via_coerce_method(self):
        """coerce dispatches to correct coercion method."""
        coercer = OCSFCoercer()
        assert coercer.coerce("src_endpoint.ip", "1.2.3.4") == "1.2.3.4"
        assert coercer.coerce("src_endpoint.port", "22") == 22
        assert coercer.coerce("process.pid", "12345") == 12345

    def test_coerce_unknown_field(self):
        """coerce returns original value for unknown fields."""
        coercer = OCSFCoercer()
        assert coercer.coerce("user", "alice") == "alice"
        assert coercer.coerce("custom_field", "value") == "value"

    def test_validate_type_ip(self):
        """validate_type checks IP validity."""
        coercer = OCSFCoercer()
        assert coercer.validate_type("src_endpoint.ip", "1.2.3.4") is True
        assert coercer.validate_type("src_endpoint.ip", "invalid") is False

    def test_validate_type_port(self):
        """validate_type checks port validity."""
        coercer = OCSFCoercer()
        assert coercer.validate_type("src_endpoint.port", 22) is True
        assert coercer.validate_type("src_endpoint.port", 65535) is True
        assert coercer.validate_type("src_endpoint.port", 65536) is False

    def test_validate_type_integer(self):
        """validate_type checks integer type."""
        coercer = OCSFCoercer()
        assert coercer.validate_type("process.pid", 123) is True
        assert coercer.validate_type("process.pid", "not int") is False

    def test_validate_type_unknown(self):
        """validate_type returns True for unknown fields (no constraint)."""
        coercer = OCSFCoercer()
        assert coercer.validate_type("user", "any value") is True

    def test_validate_type_severity_enum(self):
        """validate_type checks severity_id range."""
        coercer = OCSFCoercer()
        assert coercer.validate_type("severity_id", 3) is True
        assert coercer.validate_type("severity_id", 100) is False

    def test_validate_type_activity_enum(self):
        """validate_type checks activity_id is in VALID_ACTIVITY_IDS."""
        coercer = OCSFCoercer()
        assert coercer.validate_type("activity_id", 1) is True
        assert coercer.validate_type("activity_id", 7) is False


class TestIsValidTimestamp:
    """Tests for _is_valid_timestamp static method."""

    def test_valid_epoch_seconds(self):
        """Valid epoch seconds (2000-2100) return True."""
        coercer = OCSFCoercer()
        # 2024-01-01
        assert coercer._is_valid_timestamp(1704067200) is True

    def test_valid_epoch_milliseconds(self):
        """Valid epoch milliseconds (2000-2100) return True."""
        coercer = OCSFCoercer()
        # 2024-01-01 in ms
        assert coercer._is_valid_timestamp(1704067200000) is True

    def test_invalid_epoch_too_old(self):
        """Epoch before 2000 returns False."""
        coercer = OCSFCoercer()
        assert coercer._is_valid_timestamp(946684799) is False

    def test_invalid_epoch_future(self):
        """Epoch after 2100 returns False."""
        coercer = OCSFCoercer()
        assert coercer._is_valid_timestamp(4102444801) is False

    def test_valid_iso8601(self):
        """Valid ISO8601 returns True."""
        coercer = OCSFCoercer()
        assert coercer._is_valid_timestamp("2024-01-01T00:00:00Z") is True

    def test_valid_syslog_date(self):
        """Syslog BSD date format returns True."""
        coercer = OCSFCoercer()
        assert coercer._is_valid_timestamp("Mar 29 10:00:00") is True

    def test_valid_slash_format(self):
        """Slash-separated datetime returns True."""
        coercer = OCSFCoercer()
        assert coercer._is_valid_timestamp("2024/03/30 01:53:25.597") is True

    def test_valid_clf_format(self):
        """Apache CLF format returns True."""
        coercer = OCSFCoercer()
        assert coercer._is_valid_timestamp("15/Jan/2024:14:30:25 +0100") is True

    def test_valid_asctime_format(self):
        """Asctime format returns True."""
        coercer = OCSFCoercer()
        assert coercer._is_valid_timestamp("Mon Aug 28 08:04:30 2023") is True

    def test_valid_us_date_format(self):
        """US date format returns True."""
        coercer = OCSFCoercer()
        assert coercer._is_valid_timestamp("05/02/2025 11:31:06") is True

    def test_valid_time_only(self):
        """Time-only format returns True."""
        coercer = OCSFCoercer()
        assert coercer._is_valid_timestamp("14:30:25") is True

    def test_valid_comma_date_format(self):
        """Comma-separated date format returns True."""
        coercer = OCSFCoercer()
        assert coercer._is_valid_timestamp("Mar 28, 2026 04:39:42.196") is True


class TestIsValidMac:
    """Tests for _is_valid_mac static method."""

    def test_valid_mac_colon(self):
        """MAC with colons is valid."""
        coercer = OCSFCoercer()
        assert coercer._is_valid_mac("00:11:22:33:44:55") is True

    def test_valid_mac_hyphen(self):
        """MAC with hyphens is valid."""
        coercer = OCSFCoercer()
        assert coercer._is_valid_mac("00-11-22-33-44-55") is True

    def test_invalid_mac(self):
        """Invalid MAC returns False."""
        coercer = OCSFCoercer()
        assert coercer._is_valid_mac("not a mac") is False
        assert coercer._is_valid_mac("00:11:22:33:44") is False  # Too short


class TestConstants:
    """Tests for module-level constants."""

    def test_field_type_map_not_empty(self):
        """FIELD_TYPE_MAP contains expected field types."""
        assert len(FIELD_TYPE_MAP) > 0
        assert "src_endpoint.ip" in FIELD_TYPE_MAP
        assert "src_endpoint.port" in FIELD_TYPE_MAP

    def test_severity_map_complete(self):
        """SEVERITY_MAP contains all severity levels."""
        assert "unknown" in SEVERITY_MAP
        assert "low" in SEVERITY_MAP
        assert "critical" in SEVERITY_MAP

    def test_valid_activity_ids(self):
        """VALID_ACTIVITY_IDS contains expected IDs."""
        assert isinstance(VALID_ACTIVITY_IDS, (frozenset, set))
        assert 0 in VALID_ACTIVITY_IDS
        assert 1 in VALID_ACTIVITY_IDS
        assert 99 in VALID_ACTIVITY_IDS