"""Tests for format-aware pre-parsers."""

import pytest
from shrike.extractor.preparsers import (
    preparse, preparse_syslog_bsd, preparse_syslog_rfc5424,
    preparse_cef, preparse_json, preparse_kv, preparse_clf,
    PreparsedFields,
)
from shrike.detector.format_detector import LogFormat


class TestSyslogBSD:
    def test_basic(self):
        log = "Mar 29 10:00:00 host sshd[1234]: Accepted password for admin from 192.168.1.100 port 22"
        result = preparse_syslog_bsd(log)
        assert result is not None
        assert result.timestamp == "Mar 29 10:00:00"
        assert result.hostname == "host"
        assert result.source_app == "sshd"
        assert result.message is not None

    def test_no_pid(self):
        log = "Mar 29 10:00:00 host kernel: Out of memory"
        result = preparse_syslog_bsd(log)
        assert result is not None
        assert result.source_app == "kernel"

    def test_kv_in_message(self):
        log = "Mar 29 10:00:00 host app[99]: action=login user=admin result=success"
        result = preparse_syslog_bsd(log)
        assert result is not None
        assert "action" in result.fields
        assert result.fields["action"] == "login"


class TestSyslogRFC5424:
    def test_basic(self):
        log = "<134>1 2026-03-29T10:00:00Z host sshd 1234 - - Accepted password for admin"
        result = preparse_syslog_rfc5424(log)
        assert result is not None
        assert result.timestamp == "2026-03-29T10:00:00Z"
        assert result.hostname == "host"
        assert result.source_app == "sshd"


class TestCEF:
    def test_basic(self):
        log = "CEF:0|Security|IDS|1.0|100|Alert|5|src=192.168.1.1 dst=10.0.0.1 spt=12345 dpt=443"
        result = preparse_cef(log)
        assert result is not None
        assert result.fields["_vendor"] == "Security"
        assert result.fields["_product"] == "IDS"
        assert result.fields["src"] == "192.168.1.1"
        assert result.fields["dst"] == "10.0.0.1"
        assert result.fields["spt"] == "12345"

    def test_cef_in_syslog(self):
        log = "Mar 29 10:00:00 fw01 CEF:0|Palo|FW|1.0|1|Traffic|3|src=10.1.1.1 dst=10.2.2.2"
        result = preparse_cef(log)
        assert result is not None
        assert result.timestamp == "Mar 29 10:00:00"
        assert result.hostname == "fw01"
        assert result.fields["src"] == "10.1.1.1"


class TestJSON:
    def test_basic(self):
        log = '{"EventID": 4624, "Computer": "DC01", "TargetUserName": "admin"}'
        result = preparse_json(log)
        assert result is not None
        assert result.fields["EventID"] == 4624
        assert result.fields["Computer"] == "DC01"
        assert result.hostname == "DC01"

    def test_nested(self):
        log = '{"timestamp": "2026-01-01", "src": {"ip": "10.0.0.1", "port": 443}}'
        result = preparse_json(log)
        assert result is not None
        assert result.timestamp == "2026-01-01"
        assert "src.ip" in result.fields

    def test_invalid(self):
        assert preparse_json("not json") is None
        assert preparse_json("[1,2,3]") is None


class TestKV:
    def test_basic(self):
        log = "timestamp=2026-03-29 action=login user=admin result=success"
        result = preparse_kv(log)
        assert result is not None
        assert result.fields["action"] == "login"
        assert result.fields["user"] == "admin"

    def test_quoted_values(self):
        log = 'src="192.168.1.1" dst="10.0.0.1" action="allow"'
        result = preparse_kv(log)
        assert result is not None
        assert result.fields["src"] == "192.168.1.1"

    def test_too_few_pairs(self):
        assert preparse_kv("just one=pair") is None


class TestCLF:
    def test_basic(self):
        log = '192.168.1.1 - admin [29/Mar/2026:10:00:00 +0000] "GET /api/users HTTP/1.1" 200 1234'
        result = preparse_clf(log)
        assert result is not None
        assert result.fields["src_ip"] == "192.168.1.1"
        assert result.fields["method"] == "GET"
        assert result.fields["url"] == "/api/users"
        assert result.fields["status"] == "200"
        assert result.fields["user"] == "admin"


class TestPreparseRouter:
    def test_routes_syslog(self):
        log = "Mar 29 10:00:00 host sshd[1234]: test message"
        result = preparse(log, LogFormat.SYSLOG_BSD)
        assert result is not None
        assert result.format_type == "syslog_bsd"

    def test_routes_cef(self):
        log = "CEF:0|V|P|1|1|Name|5|src=1.2.3.4"
        result = preparse(log, LogFormat.CEF)
        assert result is not None
        assert result.format_type == "cef"

    def test_routes_json(self):
        log = '{"key": "value", "num": 42}'
        result = preparse(log, LogFormat.JSON)
        assert result is not None
        assert result.format_type == "json"

    def test_unknown_format(self):
        result = preparse("random text", LogFormat.CUSTOM)
        assert result is None
