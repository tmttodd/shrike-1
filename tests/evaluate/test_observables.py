"""Tests for ObservablesBuilder."""

from __future__ import annotations

import pytest

from shrike.evaluate.observables import (
    ObservablesBuilder,
    FIELD_OBSERVABLE_MAP,
    EXCLUDE_FIELDS,
)


class TestObservablesBuilder:
    """Tests for ObservablesBuilder class."""

    def test_build_ip_address(self):
        """IP addresses are added to observables."""
        builder = ObservablesBuilder()
        event = {"src_endpoint": {"ip": "1.2.3.4"}}

        observables = builder.build(event)

        assert len(observables) == 1
        assert observables[0]["type_id"] == 2
        assert observables[0]["type"] == "IP Address"
        assert observables[0]["value"] == "1.2.3.4"
        assert observables[0]["name"] == "src_endpoint.ip"

    def test_build_multiple_fields(self):
        """Multiple observable fields produce multiple observables."""
        builder = ObservablesBuilder()
        event = {
            "src_endpoint": {"ip": "1.2.3.4", "port": 22},
            "user": "alice",
        }

        observables = builder.build(event)

        assert len(observables) == 3
        type_ids = {o["type_id"] for o in observables}
        assert 2 in type_ids  # IP Address
        assert 11 in type_ids  # Port
        assert 4 in type_ids  # User Name

    def test_exclude_metadata_fields(self):
        """Metadata fields are excluded from observables."""
        builder = ObservablesBuilder()
        event = {
            "class_uid": 3002,
            "class_name": "Authentication",
            "user": "alice",
        }

        observables = builder.build(event)

        names = {o["name"] for o in observables}
        assert "class_uid" not in names
        assert "class_name" not in names
        assert "user" in names

    def test_exclude_empty_values(self):
        """Empty/null/None values are excluded."""
        builder = ObservablesBuilder()
        event = {
            "user": "alice",
            "src_endpoint": {"ip": ""},
            "dst_endpoint": {"ip": None},
        }

        observables = builder.build(event)

        assert len(observables) == 1
        assert observables[0]["name"] == "user"

    def test_exclude_unknown_values(self):
        """'unknown' and 'null' values are excluded."""
        builder = ObservablesBuilder()
        event = {
            "user": "unknown",
            "ip": "null",
        }

        observables = builder.build(event)

        assert len(observables) == 0

    def test_exclude_zero_values(self):
        """'0' values are excluded."""
        builder = ObservablesBuilder()
        event = {
            "user": "alice",
            "count": "0",
        }

        observables = builder.build(event)

        values = {o["value"] for o in observables}
        assert "0" not in values

    def test_deduplication(self):
        """Same type + same value produces one observable."""
        builder = ObservablesBuilder()
        event = {
            "src_endpoint": {"ip": "1.2.3.4"},
            "dst_endpoint": {"ip": "1.2.3.4"},  # Same IP
        }

        observables = builder.build(event)

        # Only one observable for IP type with value "1.2.3.4"
        ip_observables = [o for o in observables if o["type_id"] == 2]
        assert len(ip_observables) == 1

    def test_different_values_not_deduplicated(self):
        """Different values for same type produce separate observables."""
        builder = ObservablesBuilder()
        event = {
            "src_endpoint": {"ip": "1.2.3.4"},
            "dst_endpoint": {"ip": "5.6.7.8"},
        }

        observables = builder.build(event)

        ip_observables = [o for o in observables if o["type_id"] == 2]
        assert len(ip_observables) == 2

    def test_inject_adds_observables(self):
        """inject() adds observables array to event in-place."""
        builder = ObservablesBuilder()
        event = {"user": "alice", "src_endpoint": {"ip": "1.2.3.4"}}

        result = builder.inject(event)

        assert result is event
        assert "observables" in event
        assert len(event["observables"]) > 0

    def test_inject_returns_modified_event(self):
        """inject() returns the modified event."""
        builder = ObservablesBuilder()
        event = {"user": "alice"}

        result = builder.inject(event)

        assert result is event
        assert "observables" in result

    def test_count_eligible(self):
        """count_eligible counts fields that COULD produce observables."""
        builder = ObservablesBuilder()
        event = {
            "user": "alice",
            "src_endpoint": {"ip": "1.2.3.4"},
            "custom_field": "value",  # No observable type
        }

        count = builder.count_eligible(event)

        assert count == 2  # user and src_endpoint.ip

    def test_count_eligible_excludes_metadata(self):
        """count_eligible excludes metadata fields."""
        builder = ObservablesBuilder()
        event = {
            "class_uid": 3002,
            "user": "alice",
        }

        count = builder.count_eligible(event)

        assert count == 1  # Only user

    def test_get_observable_type_exact_match(self):
        """_get_observable_type returns exact match."""
        builder = ObservablesBuilder()
        type_id, type_name = builder._get_observable_type("src_endpoint.ip")
        assert type_id == 2
        assert type_name == "IP Address"

    def test_get_observable_type_suffix_fallback(self):
        """_get_observable_type falls back to suffix rules."""
        builder = ObservablesBuilder()
        type_id, type_name = builder._get_observable_type("custom.ip")
        assert type_id == 2
        assert type_name == "IP Address"

    def test_get_observable_type_unknown(self):
        """_get_observable_type returns None for unknown fields."""
        builder = ObservablesBuilder()
        type_id, type_name = builder._get_observable_type("custom_field")
        assert type_id is None
        assert type_name == ""

    def test_hostname_observable(self):
        """Hostname fields produce type_id=1 observables."""
        builder = ObservablesBuilder()
        event = {"device": {"hostname": "server1"}}

        observables = builder.build(event)

        assert len(observables) == 1
        assert observables[0]["type_id"] == 1
        assert observables[0]["type"] == "Hostname"

    def test_port_observable(self):
        """Port fields produce type_id=11 observables."""
        builder = ObservablesBuilder()
        event = {"src_endpoint": {"port": 22}}

        observables = builder.build(event)

        assert len(observables) == 1
        assert observables[0]["type_id"] == 11
        assert observables[0]["type"] == "Port"

    def test_process_observables(self):
        """Process fields produce correct observable types."""
        builder = ObservablesBuilder()
        event = {
            "process": {
                "name": "sshd",
                "pid": 12345,
                "cmd_line": "/usr/sbin/sshd",
            }
        }

        observables = builder.build(event)

        type_ids = {o["type_id"] for o in observables}
        assert 9 in type_ids  # Process Name
        assert 15 in type_ids  # Process ID
        assert 13 in type_ids  # Command Line

    def test_file_observables(self):
        """File fields produce correct observable types."""
        builder = ObservablesBuilder()
        event = {
            "file": {
                "name": "example.txt",
                "path": "/tmp/example.txt",
                "hashes": {"value": "abc123"},
            }
        }

        observables = builder.build(event)

        type_ids = {o["type_id"] for o in observables}
        assert 7 in type_ids  # File Name
        assert 8 in type_ids  # Hash

    def test_email_observables(self):
        """Email fields produce type_id=5 observables."""
        builder = ObservablesBuilder()
        event = {
            "email": {
                "from": "alice@example.com",
                "to": "bob@example.com",
            }
        }

        observables = builder.build(event)

        assert len(observables) == 2
        type_ids = {o["type_id"] for o in observables}
        assert 5 in type_ids  # Email Address

    def test_mac_observables(self):
        """MAC fields produce type_id=3 observables."""
        builder = ObservablesBuilder()
        event = {"device": {"mac": "00:11:22:33:44:55"}}

        observables = builder.build(event)

        assert len(observables) == 1
        assert observables[0]["type_id"] == 3
        assert observables[0]["type"] == "MAC Address"

    def test_url_observable(self):
        """URL fields produce type_id=6 observables."""
        builder = ObservablesBuilder()
        event = {"http_request": {"url": {"path": "/api/v1/users"}}}

        observables = builder.build(event)

        assert len(observables) == 1
        assert observables[0]["type_id"] == 6
        assert observables[0]["type"] == "URL String"

    def test_user_agent_observable(self):
        """User-Agent fields produce type_id=16 observables."""
        builder = ObservablesBuilder()
        event = {"http_request": {"user_agent": "Mozilla/5.0"}}

        observables = builder.build(event)

        assert len(observables) == 1
        assert observables[0]["type_id"] == 16
        assert observables[0]["type"] == "HTTP User-Agent"

    def test_session_uid_observable(self):
        """Session UID fields produce type_id=10 observables."""
        builder = ObservablesBuilder()
        event = {"session": {"uid": "abc123"}}

        observables = builder.build(event)

        assert len(observables) == 1
        assert observables[0]["type_id"] == 10
        assert observables[0]["type"] == "Resource UID"

    def test_nested_field_path_in_observable(self):
        """Observable name is the full dotted field path."""
        builder = ObservablesBuilder()
        event = {"src_endpoint": {"ip": "1.2.3.4"}}

        observables = builder.build(event)

        assert observables[0]["name"] == "src_endpoint.ip"

    def test_actor_user_name(self):
        """actor.user.name produces User Name observable."""
        builder = ObservablesBuilder()
        event = {"actor": {"user": {"name": "alice"}}}

        observables = builder.build(event)

        assert len(observables) == 1
        assert observables[0]["type_id"] == 4
        assert observables[0]["name"] == "actor.user.name"

    def test_actor_user_uid(self):
        """actor.user.uid produces Resource UID observable."""
        builder = ObservablesBuilder()
        event = {"actor": {"user": {"uid": "1000"}}}

        observables = builder.build(event)

        assert len(observables) == 1
        assert observables[0]["type_id"] == 10
        assert observables[0]["name"] == "actor.user.uid"

    def test_parent_process_observables(self):
        """Parent process fields produce observables."""
        builder = ObservablesBuilder()
        event = {
            "process": {
                "parent_process": {
                    "name": "bash",
                    "pid": 1234,
                }
            }
        }

        observables = builder.build(event)

        type_ids = {o["type_id"] for o in observables}
        assert 9 in type_ids  # Process Name
        assert 15 in type_ids  # Process ID

    def test_metadata_uid_excluded(self):
        """metadata.uid is NOT excluded (it's a Resource UID observable)."""
        builder = ObservablesBuilder()
        event = {"metadata": {"uid": "event-123"}}

        observables = builder.build(event)

        # metadata.uid maps to Resource UID (type_id=10), not excluded
        assert len(observables) == 1
        assert observables[0]["type_id"] == 10

    def test_time_fields_excluded(self):
        """Time fields are excluded from observables."""
        builder = ObservablesBuilder()
        event = {
            "time": "2024-01-01T00:00:00Z",
            "start_time": "2024-01-01T00:00:00Z",
            "end_time": "2024-01-01T00:00:00Z",
        }

        observables = builder.build(event)

        assert len(observables) == 0


class TestConstants:
    """Tests for module-level constants."""

    def test_field_observable_map_not_empty(self):
        """FIELD_OBSERVABLE_MAP contains expected mappings."""
        assert len(FIELD_OBSERVABLE_MAP) > 0
        assert "src_endpoint.ip" in FIELD_OBSERVABLE_MAP
        assert "user" in FIELD_OBSERVABLE_MAP

    def test_exclude_fields_set(self):
        """EXCLUDE_FIELDS is a frozenset with expected fields."""
        assert isinstance(EXCLUDE_FIELDS, frozenset)
        assert "class_uid" in EXCLUDE_FIELDS
        assert "time" in EXCLUDE_FIELDS
        assert "message" in EXCLUDE_FIELDS

    def test_ip_type_id(self):
        """src_endpoint.ip maps to type_id=2."""
        assert FIELD_OBSERVABLE_MAP["src_endpoint.ip"][0] == 2

    def test_user_type_id(self):
        """user maps to type_id=4."""
        assert FIELD_OBSERVABLE_MAP["user"][0] == 4