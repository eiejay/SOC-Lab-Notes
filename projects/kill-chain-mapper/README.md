# Kill Chain Mapper

Feed it a described incident as JSON and it maps every event two ways: to the MITRE ATT&CK tactic its technique IDs belong to, and from there to the Cyber Kill Chain phase. Then it prints the part I actually built it for: a coverage summary of which kill chain phases the incident showed and which it did not.

## Why this exists

In training, mapping an incident by hand was where the two frameworks finally clicked for me. ATT&CK tells you what the attacker did in fine detail. The kill chain tells you how far through the intrusion they got, in seven coarse steps. Writing the mapping as code forced me to decide, technique by technique, where things sit, including the awkward truth that half of ATT&CK lands inside the kill chain's single Installation phase.

The coverage summary is the analyst's part. A phase with no observed activity means one of two things: the attacker skipped it, or the telemetry that would have shown it is missing. Naming the unobserved phases in a report is how detection gaps get found before the next incident finds them first.

## What it demonstrates

- Working fluency in both frameworks: roughly forty common techniques with their tactics, and an explicit tactic to kill chain phase mapping.
- Honest reporting habits. Weaponization is called out as almost never observable from inside the victim network, so its absence is not dressed up as a finding. Unknown technique IDs in the input are reported, not silently dropped.

## Input format

```json
{
  "incident": "Name of the incident",
  "events": [
    {"time": "2026-11-08T09:02:11Z",
     "description": "What was observed",
     "techniques": ["T1566.001"]}
  ]
}
```

## How to run

```bash
python3 kill_chain_mapper.py sample_incident.json
```

## Sample output

The included scenario runs spearphish to data theft in ten events. Abridged:

```text
2026-11-08T09:04:37Z  User opened the attachment; Word spawned PowerShell with an encoded command
    T1204.002 User Execution: Malicious File -> tactic: Execution -> kill chain: Exploitation
    T1059.001 Command and Scripting Interpreter: PowerShell -> tactic: Execution -> kill chain: Exploitation
    T1027 Obfuscated Files or Information -> tactic: Defense Evasion -> kill chain: Installation

Kill chain coverage
-------------------
    Reconnaissance           not observed
    Weaponization            not observed
    Delivery                 OBSERVED
    Exploitation             OBSERVED
    Installation             OBSERVED
    Command and Control      OBSERVED
    Actions on Objectives    OBSERVED

ATT&CK tactics observed (10): Collection, Command and Control, Credential Access,
Defense Evasion, Discovery, Execution, Exfiltration, Initial Access,
Lateral Movement, Persistence
```

Ten tactics observed, and the honest gap: no Reconnaissance, which for a targeted phish almost certainly happened somewhere the victim's logs cannot see.

## Limits

- The technique table is a working subset of about forty techniques, the ones that recur in training incidents. Extending it is a matter of adding rows.
- The tactic to phase mapping is the standard one used in training material. Reasonable people map a few tactics differently; the table is in one place in the script precisely so the argument is easy to have.
