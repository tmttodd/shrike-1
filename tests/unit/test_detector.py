"""Tests for log format detector."""

import pytest

from shrike.detector.format_detector import detect_format, LogFormat


class TestSyslog:
    """Test syslog format detection."""

    def test_rfc5424(self):
        log = '<134>1 2026-03-29T10:00:00.000Z host app 1234 ID47 - message'
        assert detect_format(log) == LogFormat.SYSLOG_RFC5424

    def test_rfc3164(self):
        log = '<34>Oct 11 22:14:15 mymachine su: access denied'
        assert detect_format(log) == LogFormat.SYSLOG_RFC3164

    def test_bsd(self):
        log = 'Mar 29 10:00:00 host sshd[1234]: Accepted password for user1'
        assert detect_format(log) == LogFormat.SYSLOG_BSD

    def test_rfc3164_priority_only(self):
        log = '<165>message without month header'
        assert detect_format(log) == LogFormat.SYSLOG_RFC3164


class TestStructured:
    """Test structured format detection."""

    def test_cef(self):
        log = 'CEF:0|Security|IDS|1.0|100|Alert|5|src=192.168.1.1'
        assert detect_format(log) == LogFormat.CEF

    def test_leef(self):
        log = 'LEEF:1.0|IBM|QRadar|7.0|100|src=192.168.1.1'
        assert detect_format(log) == LogFormat.LEEF

    def test_json_simple(self):
        log = '{"level": "info", "message": "request completed", "status": 200}'
        assert detect_format(log) == LogFormat.JSON

    def test_json_array(self):
        log = '[{"event": "login"}]'
        assert detect_format(log) == LogFormat.JSON

    def test_windows_evtx_json(self):
        log = '{"EventID": 4624, "Channel": "Security", "Computer": "DC01", "Description": "Logged on"}'
        assert detect_format(log) == LogFormat.WINDOWS_EVTX_JSON

    def test_xml(self):
        log = '<?xml version="1.0"?><Event><System><EventID>4624</EventID></System></Event>'
        assert detect_format(log) == LogFormat.XML

    def test_xml_event(self):
        log = '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System/></Event>'
        assert detect_format(log) == LogFormat.XML


class TestTabular:
    """Test tabular format detection."""

    def test_csv(self):
        log = '2026-03-29,10:00:00,192.168.1.1,GET,/api,200,1234'
        assert detect_format(log) == LogFormat.CSV

    def test_tsv(self):
        log = "field1\tfield2\tfield3\tfield4\tfield5\tfield6"
        assert detect_format(log) == LogFormat.TSV

    def test_kv(self):
        log = 'timestamp=2026-03-29 action=login user=admin result=success'
        assert detect_format(log) == LogFormat.KV

    def test_w3c(self):
        log = '#Fields: date time s-ip cs-method cs-uri-stem sc-status'
        assert detect_format(log) == LogFormat.W3C


class TestWebLogs:
    """Test web access log format detection."""

    def test_clf(self):
        log = '192.168.1.1 - admin [29/Mar/2026:10:00:00 +0000] "GET /api HTTP/1.1" 200 1234'
        assert detect_format(log) == LogFormat.CLF


class TestEdgeCases:
    """Test edge cases and fallbacks."""

    def test_empty_string(self):
        assert detect_format("") == LogFormat.CUSTOM

    def test_short_string(self):
        assert detect_format("abc") == LogFormat.CUSTOM

    def test_none_becomes_custom(self):
        # detect_format should handle gracefully
        assert detect_format("random text that matches nothing") == LogFormat.CUSTOM

    def test_iso_timestamp_without_csv(self):
        # ISO-timestamped app logs are classified as syslog_bsd (structured app log)
        log = '2026-03-29T10:00:00Z host service started successfully'
        assert detect_format(log) == LogFormat.SYSLOG_BSD

    def test_cef_embedded_in_syslog(self):
        # CEF inside syslog — CEF takes priority in first 100 chars
        log = 'Mar 29 10:00:00 host CEF:0|Security|IDS|1.0|100|Alert|5|src=1.2.3.4'
        assert detect_format(log) == LogFormat.CEF
