"""Tests for projects/kill-chain-mapper/kill_chain_mapper.py.

The mapping tables are the product here, so the tests pin them: a
phishing attachment is Delivery, LSASS dumping lands in Installation
through Credential Access, and the sample incident's coverage summary
must show the five phases it earns and name Reconnaissance as missed.
Unknown technique IDs must surface, not vanish.
"""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1] / "projects" / "kill-chain-mapper"
SCRIPT = PROJECT / "kill_chain_mapper.py"
SAMPLE = PROJECT / "sample_incident.json"

spec = importlib.util.spec_from_file_location("kill_chain_mapper", SCRIPT)
mapper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mapper)


def load_sample():
    return json.loads(SAMPLE.read_text())


def test_phishing_attachment_maps_to_delivery():
    mapped, unknown = mapper.map_event({"techniques": ["T1566.001"]})
    assert unknown == []
    assert mapped[0]["tactic"] == "Initial Access"
    assert mapped[0]["phase"] == "Delivery"


def test_lsass_dumping_maps_to_credential_access():
    mapped, _ = mapper.map_event({"techniques": ["T1003.001"]})
    assert mapped[0]["tactic"] == "Credential Access"
    assert mapped[0]["phase"] == "Installation"


def test_unknown_technique_is_reported_not_dropped():
    mapped, unknown = mapper.map_event({"techniques": ["T9999.999"]})
    assert mapped == []
    assert unknown == ["T9999.999"]


def test_sample_incident_coverage():
    _, observed_phases, observed_tactics, unknown = mapper.analyze(load_sample())
    assert unknown == []
    assert observed_phases == {
        "Delivery", "Exploitation", "Installation",
        "Command and Control", "Actions on Objectives",
    }
    assert "Reconnaissance" not in observed_phases
    assert len(observed_tactics) == 10


def test_every_technique_tactic_has_a_phase():
    for tech_id, (name, tactic) in mapper.TECHNIQUES.items():
        assert tactic in mapper.TACTIC_TO_PHASE, f"{tech_id} tactic {tactic} has no kill chain phase"


def test_cli_prints_coverage_summary():
    result = subprocess.run([sys.executable, str(SCRIPT), str(SAMPLE)], capture_output=True, text=True)
    assert result.returncode == 0
    assert "Kill chain coverage" in result.stdout
    assert "Reconnaissance           not observed" in result.stdout


def test_missing_argument_prints_usage():
    result = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True)
    assert result.returncode == 1
    assert "Usage" in result.stdout
