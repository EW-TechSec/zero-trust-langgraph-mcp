import json
import shutil

import pytest

import mcp_server.server as server
from mcp_server.server import (
    list_open_ports,
    netstat_status,
    nmap_scan,
    parse_pcap,
    ping_host,
    read_scan_report,
)


def test_ping_localhost_succeeds():
    output = ping_host("127.0.0.1", count=1)
    assert isinstance(output, str)
    assert len(output) > 0


def test_ping_google_dns_is_allowed():
    output = ping_host("8.8.8.8", count=1)
    assert isinstance(output, str)
    assert len(output) > 0


def test_ping_rejects_arbitrary_external_host():
    with pytest.raises(ValueError):
        ping_host("93.184.216.34")


def test_list_open_ports_returns_json_with_expected_shape():
    output = list_open_ports("127.0.0.1", 1, 50)
    parsed = json.loads(output)
    assert parsed["host"] == "127.0.0.1"
    assert isinstance(parsed["open_ports"], list)


def test_list_open_ports_rejects_non_localhost():
    with pytest.raises(ValueError):
        list_open_ports("93.184.216.34", 1, 50)


def test_list_open_ports_rejects_google_dns():
    """Port scanning stays localhost-only even though ping allows 8.8.8.8."""
    with pytest.raises(ValueError):
        list_open_ports("8.8.8.8", 1, 50)


def test_list_open_ports_rejects_oversized_range():
    with pytest.raises(ValueError):
        list_open_ports("127.0.0.1", 1, 60000)


def test_nmap_scan_rejects_non_localhost():
    with pytest.raises(ValueError):
        nmap_scan("93.184.216.34", 1, 50)


def test_nmap_scan_rejects_oversized_range():
    with pytest.raises(ValueError):
        nmap_scan("127.0.0.1", 1, 60000)


def test_nmap_scan_missing_binary_raises_clear_error(monkeypatch):
    monkeypatch.setattr(server.shutil, "which", lambda name: None)
    with pytest.raises(RuntimeError, match="nmap is not installed"):
        nmap_scan("127.0.0.1", 1, 50)


@pytest.mark.skipif(shutil.which("nmap") is None, reason="nmap is not installed on this machine")
def test_nmap_scan_runs_when_installed():
    output = nmap_scan("127.0.0.1", 1, 50)
    assert isinstance(output, str)
    assert len(output) > 0


def test_netstat_status_returns_listening_sockets():
    output = netstat_status()
    assert isinstance(output, str)
    assert len(output) > 0


def test_netstat_status_missing_binary_raises_clear_error(monkeypatch):
    monkeypatch.setattr(server.shutil, "which", lambda name: None)
    with pytest.raises(RuntimeError, match="'ss'"):
        netstat_status()


def test_parse_pcap_reads_bundled_sample():
    output = parse_pcap("sample.pcap")
    parsed = json.loads(output)
    assert parsed["file"] == "sample.pcap"
    assert parsed["packet_count"] > 0
    assert "TCP" in parsed["protocol_counts"]


def test_parse_pcap_blocks_path_traversal():
    with pytest.raises(ValueError):
        parse_pcap("../../etc/passwd")


def test_parse_pcap_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        parse_pcap("does_not_exist.pcap")


def test_read_scan_report_reads_bundled_sample():
    output = read_scan_report("sample_scan_report.json")
    parsed = json.loads(output)
    assert parsed["scan_id"] == "demo-scan-0001"
    assert isinstance(parsed["open_ports"], list)


def test_read_scan_report_blocks_path_traversal():
    with pytest.raises(ValueError):
        read_scan_report("../../../etc/passwd")
