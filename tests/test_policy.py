from agent.policy import ALLOWED_TOOLS, SENSITIVE_TOOLS, evaluate_policy


def test_unknown_tool_is_denied():
    result = evaluate_policy("delete_everything", {})
    assert result.allowed is False
    assert "not on the tool allowlist" in result.reason


def test_ping_localhost_is_allowed_and_not_sensitive():
    result = evaluate_policy("ping_host", {"host": "127.0.0.1", "count": 4})
    assert result.allowed is True
    assert result.sensitive is False
    assert result.validated_args == {"host": "127.0.0.1", "count": 4}


def test_ping_google_dns_is_allowed():
    """8.8.8.8 is a published public connectivity-test target, not a real
    target being probed, so ping (only) is allowed to reach it."""
    result = evaluate_policy("ping_host", {"host": "8.8.8.8", "count": 4})
    assert result.allowed is True
    assert result.sensitive is False


def test_ping_arbitrary_external_host_is_denied():
    result = evaluate_policy("ping_host", {"host": "93.184.216.34", "count": 4})
    assert result.allowed is False
    assert "not on the allowlist" in result.reason


def test_ping_count_out_of_bounds_is_denied():
    result = evaluate_policy("ping_host", {"host": "127.0.0.1", "count": 999})
    assert result.allowed is False


def test_list_open_ports_rejects_google_dns():
    """Port scanning stays localhost-only even though ping allows 8.8.8.8."""
    result = evaluate_policy(
        "list_open_ports", {"host": "8.8.8.8", "start_port": 1, "end_port": 100}
    )
    assert result.allowed is False


def test_list_open_ports_is_marked_sensitive():
    assert "list_open_ports" in SENSITIVE_TOOLS
    result = evaluate_policy("list_open_ports", {"host": "127.0.0.1", "start_port": 1, "end_port": 100})
    assert result.allowed is True
    assert result.sensitive is True


def test_list_open_ports_range_too_wide_is_denied():
    result = evaluate_policy(
        "list_open_ports", {"host": "127.0.0.1", "start_port": 1, "end_port": 60000}
    )
    assert result.allowed is False


def test_list_open_ports_inverted_range_is_denied():
    result = evaluate_policy(
        "list_open_ports", {"host": "127.0.0.1", "start_port": 500, "end_port": 100}
    )
    assert result.allowed is False


def test_nmap_scan_is_marked_sensitive():
    assert "nmap_scan" in SENSITIVE_TOOLS
    result = evaluate_policy("nmap_scan", {"host": "127.0.0.1", "start_port": 1, "end_port": 100})
    assert result.allowed is True
    assert result.sensitive is True


def test_nmap_scan_rejects_non_localhost():
    result = evaluate_policy("nmap_scan", {"host": "93.184.216.34", "start_port": 1, "end_port": 100})
    assert result.allowed is False


def test_nmap_scan_range_too_wide_is_denied():
    result = evaluate_policy("nmap_scan", {"host": "127.0.0.1", "start_port": 1, "end_port": 60000})
    assert result.allowed is False


def test_netstat_status_is_allowed_and_not_sensitive():
    """netstat_status only reads local kernel state, no target to probe, so it
    isn't sensitive even though the two port-scanning tools are."""
    assert "netstat_status" not in SENSITIVE_TOOLS
    result = evaluate_policy("netstat_status", {})
    assert result.allowed is True
    assert result.sensitive is False


def test_parse_pcap_allowed_filename():
    result = evaluate_policy("parse_pcap", {"filename": "sample.pcap"})
    assert result.allowed is True
    assert result.sensitive is False


def test_parse_pcap_path_traversal_attempt_is_denied():
    result = evaluate_policy("parse_pcap", {"filename": "../../etc/passwd"})
    assert result.allowed is False


def test_read_scan_report_wrong_filename_is_denied():
    result = evaluate_policy("read_scan_report", {"filename": "not_the_real_report.json"})
    assert result.allowed is False


def test_every_allowed_tool_has_an_arg_model():
    from agent.policy import TOOL_ARG_MODELS

    assert set(TOOL_ARG_MODELS) == ALLOWED_TOOLS
