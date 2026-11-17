"""Tests for projects/proxy-log-analyzer/proxy_log_analyzer.py.

The two cases that matter: a client calling the same host every five
minutes like clockwork must flag as a possible beacon, and a client
calling at human, irregular intervals must not. Everything else pins
the simpler rules (upload size, rare domains, suspicious hosts) so a
refactor cannot quietly change what the tool calls a finding.
"""

import importlib.util
import subprocess
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1] / "projects" / "proxy-log-analyzer"
SCRIPT = PROJECT / "proxy_log_analyzer.py"
SAMPLE_LOG = PROJECT / "sample_proxy.log"

spec = importlib.util.spec_from_file_location("proxy_log_analyzer", SCRIPT)
analyzer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(analyzer)


def run_cli(*args):
    return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True)


def test_sample_log_parses_fully():
    requests, skipped = analyzer.parse_log(str(SAMPLE_LOG))
    assert len(requests) == 30
    assert skipped == 0


def test_beacon_is_flagged():
    requests, _ = analyzer.parse_log(str(SAMPLE_LOG))
    beacons = analyzer.find_beacons(requests)
    assert len(beacons) == 1
    assert beacons[0]["host"] == "updates-cdn.example.xyz"
    assert beacons[0]["client"] == "192.168.1.44"


def test_irregular_heartbeat_is_not_a_beacon():
    requests, _ = analyzer.parse_log(str(SAMPLE_LOG))
    hosts = {b["host"] for b in analyzer.find_beacons(requests)}
    assert "telemetry.vendor-example.com" not in hosts


def test_large_upload_is_flagged():
    requests, _ = analyzer.parse_log(str(SAMPLE_LOG))
    uploads = analyzer.find_large_uploads(requests, analyzer.DEFAULT_UPLOAD_THRESHOLD)
    assert len(uploads) == 1
    assert uploads[0]["up"] == 8945211
    assert uploads[0]["user"] == "dlee"


def test_rare_and_suspicious_hosts():
    requests, _ = analyzer.parse_log(str(SAMPLE_LOG))
    rare, _ = analyzer.find_rare_domains(requests)
    assert "secure-login-verify.example.click" in rare
    assert "www.google.com" not in rare
    suspicious = analyzer.find_suspicious_hosts(requests)
    assert "fileshare-drop.example.top" in suspicious
    assert "www.bbc.com" not in suspicious


def test_cli_report_mentions_the_beacon():
    result = run_cli(str(SAMPLE_LOG))
    assert result.returncode == 0
    assert "Possible beaconing (1)" in result.stdout
    assert "updates-cdn.example.xyz" in result.stdout


def test_missing_argument_prints_usage():
    result = run_cli()
    assert result.returncode == 1
    assert "Usage" in result.stdout
