# SOC Lab Notes

Security Operations Center (SOC) analyst training labs, workflows, and reference notes.

This repository collects the working documents from my SOC training: how an alert gets triaged, how an incident gets documented, and how logs get read during an investigation. It is a practice and reference repository, built from hands-on lab work and coursework in security operations (CompTIA Security+ and CySA+ level material).

## Projects

Three small, working projects that mirror daily Tier 1 SOC tasks:

1. [Brute Force Detector](projects/brute-force-detector/): a Python script that reads a Linux authentication log and flags source IPs with repeated failed logins, the most common real alert in any SOC queue.
2. [Phishing Email Analyzer](projects/phishing-email-analyzer/): a header and content analysis walkthrough, worked end to end on an example phish.
3. [Splunk Detection Pack](projects/splunk-detection-pack/): five documented Splunk searches for common detections, each with purpose, SPL, and tuning notes.

## Reference documents

- [Alert Triage Workflow](triage-workflow.md): the step-by-step process for receiving, validating, prioritizing, and escalating a security alert.
- [Incident Report Template](incident-report-template.md): a fill-in report structure for documenting an incident from detection to closure.
- [Log Analysis Notes](log-analysis-notes.md): notes on reading authentication, network, and endpoint logs during triage.

## Skills practiced

- Alert triage and escalation in a SIEM environment (Splunk)
- Log analysis: Windows Event Logs, authentication events, firewall and proxy data
- Incident documentation and shift handoff notes
- Detection concepts: brute force, phishing, malware callbacks, privilege escalation
- Classifying attacker behavior with the MITRE ATT&CK framework

## Tools

- Splunk (search and reporting)
- Python 3 for log parsing
- Linux command line for log review
- MITRE ATT&CK

## License

MIT
