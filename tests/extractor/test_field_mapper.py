"""Tests for FieldMapper (OCSF field name mapper)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def aliases_file(tmp_path):
    """Create a temporary aliases file."""
    aliases_path = tmp_path / "aliases.json"
    aliases_path.write_text(json.dumps({
        "user": "user",
        "username": "user",
        "sourceAddress": "src_endpoint.ip",
        "sourcePort": "src_endpoint.port",
        "destAddress": "dst_endpoint.ip",
        "destPort": "dst_endpoint.port",
        "timestamp": "time",
        "severity": "severity",
        "action": "activity_name",
        "message": "message",
    }))
    return aliases_path


class TestFieldMapper:
    """Tests for FieldMapper."""

    def test_init_loads_aliases(self, aliases_file):
        """Initializes and loads aliases from file."""
        from shrike.extractor.field_mapper import FieldMapper

        mapper = FieldMapper(aliases_path=aliases_file)
        assert mapper.alias_count == 10

    def test_init_missing_file(self):
        """Handles missing aliases file gracefully."""
        from shrike.extractor.field_mapper import FieldMapper

        mapper = FieldMapper(aliases_path=Path("/nonexistent"))
        assert mapper.alias_count == 0

    def test_map_field_exact_match(self, aliases_file):
        """map_field returns exact alias match."""
        from shrike.extractor.field_mapper import FieldMapper

        mapper = FieldMapper(aliases_path=aliases_file)
        assert mapper.map_field("user") == "user"
        assert mapper.map_field("username") == "user"

    def test_map_field_leaf_name(self, aliases_file):
        """map_field tries leaf name when full path not found."""
        from shrike.extractor.field_mapper import FieldMapper

        mapper = FieldMapper(aliases_path=aliases_file)
        # "event.user" not in aliases, but "user" is
        assert mapper.map_field("event.user") == "user"

    def test_map_field_ip_heuristic(self, aliases_file):
        """map_field uses IP heuristic for IP-like values."""
        from shrike.extractor.field_mapper import FieldMapper

        mapper = FieldMapper(aliases_path=aliases_file)
        # Field name not in aliases, but value looks like IP
        assert mapper.map_field("addr", "192.168.1.1") == "src_endpoint.ip"

    def test_map_field_ip_with_src_context(self, aliases_file):
        """map_field maps IP to src_endpoint when context suggests source."""
        from shrike.extractor.field_mapper import FieldMapper

        mapper = FieldMapper(aliases_path=aliases_file)
        assert mapper.map_field("src_ip", "10.0.0.1") == "src_endpoint.ip"
        assert mapper.map_field("source_ip", "10.0.0.1") == "src_endpoint.ip"
        assert mapper.map_field("client_ip", "10.0.0.1") == "src_endpoint.ip"

    def test_map_field_ip_with_dst_context(self, aliases_file):
        """map_field maps IP to dst_endpoint when context suggests destination."""
        from shrike.extractor.field_mapper import FieldMapper

        mapper = FieldMapper(aliases_path=aliases_file)
        assert mapper.map_field("dst_ip", "10.0.0.1") == "dst_endpoint.ip"
        assert mapper.map_field("dest_ip", "10.0.0.1") == "dst_endpoint.ip"
        assert mapper.map_field("server_ip", "10.0.0.1") == "dst_endpoint.ip"

    def test_map_field_port(self, aliases_file):
        """map_field maps port fields."""
        from shrike.extractor.field_mapper import FieldMapper

        mapper = FieldMapper(aliases_path=aliases_file)
        assert mapper.map_field("sport") == "src_endpoint.port"
        assert mapper.map_field("src_port") == "src_endpoint.port"
        assert mapper.map_field("dport") == "dst_endpoint.port"
        assert mapper.map_field("dest_port") == "dst_endpoint.port"

    def test_map_field_user(self, aliases_file):
        """map_field maps user fields."""
        from shrike.extractor.field_mapper import FieldMapper

        mapper = FieldMapper(aliases_path=aliases_file)
        assert mapper.map_field("user") == "user"
        assert mapper.map_field("username") == "user"
        assert mapper.map_field("login") == "user"

    def test_map_field_timestamp(self, aliases_file):
        """map_field maps timestamp fields."""
        from shrike.extractor.field_mapper import FieldMapper

        mapper = FieldMapper(aliases_path=aliases_file)
        assert mapper.map_field("timestamp") == "time"
        assert mapper.map_field("time") == "time"
        assert mapper.map_field("date") == "time"

    def test_map_field_severity(self, aliases_file):
        """map_field maps severity fields."""
        from shrike.extractor.field_mapper import FieldMapper

        mapper = FieldMapper(aliases_path=aliases_file)
        assert mapper.map_field("severity") == "severity"
        assert mapper.map_field("sev") == "severity"
        assert mapper.map_field("priority") == "severity"

    def test_map_field_process(self, aliases_file):
        """map_field maps process fields."""
        from shrike.extractor.field_mapper import FieldMapper

        mapper = FieldMapper(aliases_path=aliases_file)
        assert mapper.map_field("process") == "process.name"
        assert mapper.map_field("pid") == "process.pid"
        assert mapper.map_field("process_id") == "process.pid"

    def test_map_field_hostname(self, aliases_file):
        """map_field maps hostname fields."""
        from shrike.extractor.field_mapper import FieldMapper

        mapper = FieldMapper(aliases_path=aliases_file)
        assert mapper.map_field("hostname") == "device.hostname"
        assert mapper.map_field("host") == "device.hostname"
        assert mapper.map_field("computer") == "device.hostname"

    def test_map_field_url(self, aliases_file):
        """map_field maps URL fields."""
        from shrike.extractor.field_mapper import FieldMapper

        mapper = FieldMapper(aliases_path=aliases_file)
        assert mapper.map_field("url") == "http_request.url.path"
        assert mapper.map_field("uri") == "http_request.url.path"
        assert mapper.map_field("path") == "http_request.url.path"

    def test_map_field_http_method(self, aliases_file):
        """map_field maps HTTP method fields with known values."""
        from shrike.extractor.field_mapper import FieldMapper

        mapper = FieldMapper(aliases_path=aliases_file)
        assert mapper.map_field("method", "GET") == "http_request.http_method"
        assert mapper.map_field("method", "POST") == "http_request.http_method"
        assert mapper.map_field("method", "PUT") == "http_request.http_method"

    def test_map_field_status(self, aliases_file):
        """map_field maps status fields."""
        from shrike.extractor.field_mapper import FieldMapper

        mapper = FieldMapper(aliases_path=aliases_file)
        assert mapper.map_field("status") == "status"
        assert mapper.map_field("result") == "status"
        assert mapper.map_field("status_code") == "status"

    def test_map_field_returns_none_for_unknown(self, aliases_file):
        """map_field returns None for completely unknown fields."""
        from shrike.extractor.field_mapper import FieldMapper

        mapper = FieldMapper(aliases_path=aliases_file)
        assert mapper.map_field("completely_unknown_field_xyz") is None

    def test_map_all(self, aliases_file):
        """map_all maps all fields in a dict."""
        from shrike.extractor.field_mapper import FieldMapper

        mapper = FieldMapper(aliases_path=aliases_file)
        fields = {"user": "admin", "ip": "192.168.1.1", "unknown": "value"}
        result = mapper.map_all(fields)

        assert ("user" in result or ("src_endpoint.ip" in result and "unknown" not in result))
        assert len(result) >= 1

    def test_map_all_excludes_none_values(self, aliases_file):
        """map_all excludes fields with None values."""
        from shrike.extractor.field_mapper import FieldMapper

        mapper = FieldMapper(aliases_path=aliases_file)
        fields = {"user": "admin", "ip": None}
        result = mapper.map_all(fields)

        # None values should be excluded
        for ocsf_path, (vendor_field, value) in result.items():
            assert value is not None

    def test_embedding_match(self, aliases_file):
        """_embedding_match uses embedding mapper when available."""
        from shrike.extractor.field_mapper import FieldMapper

        mapper = FieldMapper(aliases_path=aliases_file)
        mapper._embedding_available = None  # Not checked yet

        with patch.object(mapper, "_get_embedding_mapper") as mock_get:
            mock_mapper = MagicMock()
            mock_mapper.map_field.return_value = ("user", 0.85)
            mock_get.return_value = mock_mapper

            result = mapper._embedding_match("userName")
            assert result == "user"

    def test_embedding_match_unavailable(self, aliases_file):
        """_embedding_match returns None when mapper unavailable."""
        from shrike.extractor.field_mapper import FieldMapper

        mapper = FieldMapper(aliases_path=aliases_file)
        mapper._embedding_available = False

        result = mapper._embedding_match("userName")
        assert result is None

    def test_is_ip_value(self):
        """_is_ip_value correctly identifies IP addresses."""
        from shrike.extractor.field_mapper import FieldMapper

        assert FieldMapper._is_ip_value("192.168.1.1") is True
        assert FieldMapper._is_ip_value("10.0.0.1") is True
        assert FieldMapper._is_ip_value("255.255.255.255") is True
        assert FieldMapper._is_ip_value("not.an.ip") is False
        assert FieldMapper._is_ip_value("192.168.1.1/24") is False
        assert FieldMapper._is_ip_value("") is False

    def test_alias_count_property(self, aliases_file):
        """alias_count returns number of loaded aliases."""
        from shrike.extractor.field_mapper import FieldMapper

        mapper = FieldMapper(aliases_path=aliases_file)
        assert mapper.alias_count == 10

    def test_fuzzy_match_email(self, aliases_file):
        """_fuzzy_match identifies email values."""
        from shrike.extractor.field_mapper import FieldMapper

        mapper = FieldMapper(aliases_path=aliases_file)
        result = mapper._fuzzy_match("email_field", "user@example.com")
        assert result == "user"

    def test_fuzzy_match_file(self, aliases_file):
        """_fuzzy_match maps file-related fields."""
        from shrike.extractor.field_mapper import FieldMapper

        mapper = FieldMapper(aliases_path=aliases_file)
        assert mapper._fuzzy_match("filename") == "file.name"
        assert mapper._fuzzy_match("filepath") == "file.path"
        assert mapper._fuzzy_match("hash") == "file.hashes.value"

    def test_fuzzy_match_dns(self, aliases_file):
        """_fuzzy_match maps DNS-related fields."""
        from shrike.extractor.field_mapper import FieldMapper

        mapper = FieldMapper(aliases_path=aliases_file)
        assert mapper._fuzzy_match("dns_query") == "query.hostname"
        assert mapper._fuzzy_match("domain_name") == "query.hostname"


class TestFuzzyMatch:
    """Tests for fuzzy matching strategies."""

    def test_ip_value_detection(self):
        """Correctly detects IP address values."""
        from shrike.extractor.field_mapper import FieldMapper

        # Valid IPs
        assert FieldMapper._is_ip_value("192.168.1.1") is True
        assert FieldMapper._is_ip_value("10.0.0.1") is True
        assert FieldMapper._is_ip_value("172.16.0.1") is True
        assert FieldMapper._is_ip_value("0.0.0.0") is True
        assert FieldMapper._is_ip_value("255.255.255.255") is True

        # Invalid IPs
        assert FieldMapper._is_ip_value("256.1.1.1") is False
        assert FieldMapper._is_ip_value("1.2.3.4.5") is False
        assert FieldMapper._is_ip_value("not.ip") is False
        assert FieldMapper._is_ip_value("") is False
        assert FieldMapper._is_ip_value("192.168.1") is False

    def test_context_aware_ip_mapping(self):
        """Context-aware IP mapping (source vs destination)."""
        from shrike.extractor.field_mapper import FieldMapper

        mapper = FieldMapper(aliases_path=Path("/nonexistent"))

        # Source indicators
        for field in ["src", "source", "client", "caller", "remote", "origin"]:
            result = mapper._fuzzy_match(field, "192.168.1.1")
            assert result == "src_endpoint.ip", f"Field '{field}' should map to src_endpoint.ip"

        # Destination indicators
        for field in ["dst", "dest", "server", "target"]:
            result = mapper._fuzzy_match(field, "192.168.1.1")
            assert result == "dst_endpoint.ip", f"Field '{field}' should map to dst_endpoint.ip"

    def test_port_mapping(self):
        """Port field mapping."""
        from shrike.extractor.field_mapper import FieldMapper

        mapper = FieldMapper(aliases_path=Path("/nonexistent"))

        assert mapper._fuzzy_match("sport") == "src_endpoint.port"
        assert mapper._fuzzy_match("src_port") == "src_endpoint.port"
        assert mapper._fuzzy_match("source_port") == "src_endpoint.port"
        assert mapper._fuzzy_match("dport") == "dst_endpoint.port"
        assert mapper._fuzzy_match("dst_port") == "dst_endpoint.port"
        assert mapper._fuzzy_match("dest_port") == "dst_endpoint.port"

    def test_process_mapping(self):
        """Process field mapping."""
        from shrike.extractor.field_mapper import FieldMapper

        mapper = FieldMapper(aliases_path=Path("/nonexistent"))

        assert mapper._fuzzy_match("process") == "process.name"
        assert mapper._fuzzy_match("proc") == "process.name"
        assert mapper._fuzzy_match("pid") == "process.pid"
        assert mapper._fuzzy_match("process_id") == "process.pid"
        assert mapper._fuzzy_match("cmdline") == "process.cmd_line"
        assert mapper._fuzzy_match("exe") == "process.file.path"

    def test_hostname_mapping(self):
        """Hostname/device field mapping."""
        from shrike.extractor.field_mapper import FieldMapper

        mapper = FieldMapper(aliases_path=Path("/nonexistent"))

        assert mapper._fuzzy_match("hostname") == "device.hostname"
        assert mapper._fuzzy_match("host") == "device.hostname"
        assert mapper._fuzzy_match("computer") == "device.hostname"
        assert mapper._fuzzy_match("node") == "device.hostname"
        assert mapper._fuzzy_match("fqdn") == "device.hostname"

    def test_time_mapping(self):
        """Time/timestamp field mapping."""
        from shrike.extractor.field_mapper import FieldMapper

        mapper = FieldMapper(aliases_path=Path("/nonexistent"))

        assert mapper._fuzzy_match("timestamp") == "time"
        assert mapper._fuzzy_match("time") == "time"
        assert mapper._fuzzy_match("ts") == "time"
        assert mapper._fuzzy_match("date") == "time"
        assert mapper._fuzzy_match("datetime") == "time"
        assert mapper._fuzzy_match("created_at") == "time"

    def test_action_mapping(self):
        """Action/activity field mapping."""
        from shrike.extractor.field_mapper import FieldMapper

        mapper = FieldMapper(aliases_path=Path("/nonexistent"))

        assert mapper._fuzzy_match("action") == "activity_name"
        assert mapper._fuzzy_match("activity") == "activity_name"
        assert mapper._fuzzy_match("operation") == "activity_name"
        assert mapper._fuzzy_match("method") == "activity_name"

    def test_message_mapping(self):
        """Message field mapping."""
        from shrike.extractor.field_mapper import FieldMapper

        mapper = FieldMapper(aliases_path=Path("/nonexistent"))

        assert mapper._fuzzy_match("message") == "message"
        assert mapper._fuzzy_match("msg") == "message"
        assert mapper._fuzzy_match("description") == "message"
        assert mapper._fuzzy_match("text") == "message"

    def test_protocol_mapping(self):
        """Protocol field mapping."""
        from shrike.extractor.field_mapper import FieldMapper

        mapper = FieldMapper(aliases_path=Path("/nonexistent"))

        assert mapper._fuzzy_match("protocol") == "connection_info.protocol_name"
        assert mapper._fuzzy_match("proto") == "connection_info.protocol_name"
        assert mapper._fuzzy_match("transport") == "connection_info.protocol_name"

    def test_severity_mapping(self):
        """Severity field mapping."""
        from shrike.extractor.field_mapper import FieldMapper

        mapper = FieldMapper(aliases_path=Path("/nonexistent"))

        assert mapper._fuzzy_match("severity") == "severity"
        assert mapper._fuzzy_match("sev") == "severity"
        assert mapper._fuzzy_match("priority") == "severity"
        assert mapper._fuzzy_match("prio") == "severity"