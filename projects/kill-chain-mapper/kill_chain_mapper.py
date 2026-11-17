"""Kill chain mapper.

Takes a described incident as JSON, where each event carries the MITRE
ATT&CK technique IDs observed in it, and maps the incident two ways:

  - every event to the ATT&CK tactic its techniques belong to
  - every tactic to the Cyber Kill Chain phase it falls in

The point of the exercise is the coverage summary at the end: which kill
chain phases the incident actually showed, and which it did not. The
phases you did not observe are where your detection gaps and your
assumptions live, and saying so out loud is half of incident reporting.

Input format:

  {
    "incident": "Name of the incident",
    "events": [
      {"time": "2026-11-08T09:02:11Z",
       "description": "What was observed",
       "techniques": ["T1566.001"]}
    ]
  }

Usage:
  python3 kill_chain_mapper.py sample_incident.json
"""

import json
import sys

# Technique ID -> (technique name, ATT&CK tactic). A working subset: the
# techniques that show up again and again in the incidents a Tier 1
# analyst trains on. Unknown IDs are reported, not silently dropped.
TECHNIQUES = {
    "T1566.001": ("Spearphishing Attachment", "Initial Access"),
    "T1566.002": ("Spearphishing Link", "Initial Access"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1133": ("External Remote Services", "Initial Access"),
    "T1078": ("Valid Accounts", "Initial Access"),
    "T1204.002": ("User Execution: Malicious File", "Execution"),
    "T1059.001": ("Command and Scripting Interpreter: PowerShell", "Execution"),
    "T1059.003": ("Command and Scripting Interpreter: Windows Command Shell", "Execution"),
    "T1203": ("Exploitation for Client Execution", "Execution"),
    "T1547.001": ("Boot or Logon Autostart Execution: Registry Run Keys", "Persistence"),
    "T1053.005": ("Scheduled Task", "Persistence"),
    "T1505.003": ("Server Software Component: Web Shell", "Persistence"),
    "T1055": ("Process Injection", "Privilege Escalation"),
    "T1134": ("Access Token Manipulation", "Privilege Escalation"),
    "T1562.001": ("Impair Defenses: Disable or Modify Tools", "Defense Evasion"),
    "T1070.001": ("Indicator Removal: Clear Windows Event Logs", "Defense Evasion"),
    "T1027": ("Obfuscated Files or Information", "Defense Evasion"),
    "T1140": ("Deobfuscate/Decode Files or Information", "Defense Evasion"),
    "T1003.001": ("OS Credential Dumping: LSASS Memory", "Credential Access"),
    "T1555.003": ("Credentials from Password Stores: Web Browsers", "Credential Access"),
    "T1110.002": ("Brute Force: Password Cracking", "Credential Access"),
    "T1083": ("File and Directory Discovery", "Discovery"),
    "T1018": ("Remote System Discovery", "Discovery"),
    "T1057": ("Process Discovery", "Discovery"),
    "T1021.002": ("Remote Services: SMB/Windows Admin Shares", "Lateral Movement"),
    "T1021.001": ("Remote Services: Remote Desktop Protocol", "Lateral Movement"),
    "T1570": ("Lateral Tool Transfer", "Lateral Movement"),
    "T1005": ("Data from Local System", "Collection"),
    "T1560.001": ("Archive Collected Data: Archive via Utility", "Collection"),
    "T1071.001": ("Application Layer Protocol: Web Protocols", "Command and Control"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1573.002": ("Encrypted Channel: Asymmetric Cryptography", "Command and Control"),
    "T1048.003": ("Exfiltration Over Unencrypted Non-C2 Protocol", "Exfiltration"),
    "T1567.002": ("Exfiltration to Cloud Storage Service", "Exfiltration"),
    "T1486": ("Data Encrypted for Impact", "Impact"),
    "T1490": ("Inhibit System Recovery", "Impact"),
}

# ATT&CK tactic -> Cyber Kill Chain phase. ATT&CK is finer grained than
# the kill chain, so several tactics share a phase; that mismatch is
# worth seeing instead of hiding.
TACTIC_TO_PHASE = {
    "Reconnaissance": "Reconnaissance",
    "Initial Access": "Delivery",
    "Execution": "Exploitation",
    "Persistence": "Installation",
    "Privilege Escalation": "Installation",
    "Defense Evasion": "Installation",
    "Credential Access": "Installation",
    "Discovery": "Installation",
    "Lateral Movement": "Installation",
    "Collection": "Actions on Objectives",
    "Command and Control": "Command and Control",
    "Exfiltration": "Actions on Objectives",
    "Impact": "Actions on Objectives",
}

KILL_CHAIN_PHASES = [
    "Reconnaissance",
    "Weaponization",
    "Delivery",
    "Exploitation",
    "Installation",
    "Command and Control",
    "Actions on Objectives",
]


def map_event(event):
    """Resolve one event's technique IDs to names, tactics, and phases."""
    mapped = []
    unknown = []
    for tech_id in event.get("techniques", []):
        if tech_id in TECHNIQUES:
            name, tactic = TECHNIQUES[tech_id]
            mapped.append({
                "id": tech_id, "name": name, "tactic": tactic,
                "phase": TACTIC_TO_PHASE[tactic],
            })
        else:
            unknown.append(tech_id)
    return mapped, unknown


def analyze(incident):
    """Return per-event mappings plus the set of observed phases and tactics."""
    rows = []
    observed_phases = set()
    observed_tactics = set()
    unknown_ids = []
    for event in incident.get("events", []):
        mapped, unknown = map_event(event)
        unknown_ids.extend(unknown)
        for m in mapped:
            observed_phases.add(m["phase"])
            observed_tactics.add(m["tactic"])
        rows.append({"event": event, "mapped": mapped, "unknown": unknown})
    return rows, observed_phases, observed_tactics, unknown_ids


def build_report(incident):
    rows, observed_phases, observed_tactics, unknown_ids = analyze(incident)
    lines = []
    lines.append(f"Kill chain mapping: {incident.get('incident', 'unnamed incident')}")
    lines.append("=" * 60)
    lines.append("")
    lines.append("Event by event")
    lines.append("--------------")
    for row in rows:
        event = row["event"]
        lines.append(f"{event.get('time', '?')}  {event.get('description', '')}")
        if not row["mapped"] and not row["unknown"]:
            lines.append("    (no techniques recorded for this event)")
        for m in row["mapped"]:
            lines.append(f"    {m['id']} {m['name']} -> tactic: {m['tactic']} -> kill chain: {m['phase']}")
        for tech_id in row["unknown"]:
            lines.append(f"    {tech_id} -> not in this tool's technique table, mapping skipped")
    lines.append("")
    lines.append("Kill chain coverage")
    lines.append("-------------------")
    for phase in KILL_CHAIN_PHASES:
        mark = "OBSERVED" if phase in observed_phases else "not observed"
        lines.append(f"    {phase:<24} {mark}")
    lines.append("")
    lines.append(f"ATT&CK tactics observed ({len(observed_tactics)}): {', '.join(sorted(observed_tactics)) or 'none'}")
    if "Weaponization" not in observed_phases:
        lines.append("")
        lines.append("Note: Weaponization is almost never observable from inside the victim")
        lines.append("network. Its absence here is expected and is not, by itself, a gap.")
    missed = [p for p in KILL_CHAIN_PHASES if p not in observed_phases and p != "Weaponization"]
    if missed:
        lines.append(f"Phases with no observed activity: {', '.join(missed)}. Either the")
        lines.append("attacker skipped them, or the telemetry that would show them is missing.")
        lines.append("Deciding which of those is true is the follow-up work.")
    if unknown_ids:
        lines.append("")
        lines.append(f"Unknown technique IDs in input: {', '.join(sorted(set(unknown_ids)))}")
    return "\n".join(lines) + "\n"


def main(argv):
    if len(argv) != 2:
        print("Usage: python3 kill_chain_mapper.py <incident.json>")
        return 1
    with open(argv[1]) as handle:
        incident = json.load(handle)
    print(build_report(incident), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
