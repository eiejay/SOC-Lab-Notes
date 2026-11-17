"""Tests for projects/email-header-analyzer/email_header_analyzer.py.

Three sample messages, three verdicts, and the tests keep them that
way: the genuine alert must score zero, the sloppy marketing mail must
land in the middle, and the phish must trip the authentication,
alignment, and display name checks all at once. If a scoring change
moves any of those, it should have to argue with these tests first.
"""

import importlib.util
import subprocess
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1] / "projects" / "email-header-analyzer"
SCRIPT = PROJECT / "email_header_analyzer.py"
SAMPLES = PROJECT / "samples"

spec = importlib.util.spec_from_file_location("email_header_analyzer", SCRIPT)
headers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(headers)


def findings_text(findings):
    return " ".join(text for _, text in findings)


def test_legitimate_message_scores_zero():
    score, findings, info = headers.analyze(str(SAMPLES / "legitimate.eml"))
    assert score == 0
    assert findings == []
    assert info["auth"] == {"spf": "pass", "dkim": "pass", "dmarc": "pass",
                            "dkim_domain": "accounts.google.com"}
    assert headers.verdict_for(score).startswith("LOW RISK")


def test_phishing_message_fails_everything():
    score, findings, _ = headers.analyze(str(SAMPLES / "phishing.eml"))
    text = findings_text(findings)
    assert score >= 5
    assert headers.verdict_for(score).startswith("HIGH RISK")
    assert "SPF failed" in text
    assert "DMARC failed" in text
    assert "Display name claims" in text
    assert "does not align" in text
    assert "Reply-To domain" in text


def test_suspicious_middle_case():
    score, findings, _ = headers.analyze(str(SAMPLES / "suspicious.eml"))
    assert score == 2
    assert headers.verdict_for(score).startswith("SUSPICIOUS")
    assert "Reply-To domain" in findings_text(findings)


def test_registrable_domain_alignment():
    assert headers.registrable("mail.accounts.google.com") == "google.com"
    assert headers.registrable("google.com") == "google.com"


def test_cli_prints_verdict():
    result = subprocess.run([sys.executable, str(SCRIPT), str(SAMPLES / "phishing.eml")],
                            capture_output=True, text=True)
    assert result.returncode == 0
    assert "HIGH RISK" in result.stdout
    assert "Risk score: 13" in result.stdout


def test_missing_argument_prints_usage():
    result = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True)
    assert result.returncode == 1
    assert "Usage" in result.stdout
