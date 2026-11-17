"""EDR telemetry analyzer.

Reads endpoint process creation events in a Sysmon style JSON format and
raises alerts on the process behavior patterns that endpoint detection
tools are built around:

  - an Office application spawning a shell or scripting host
  - PowerShell running an encoded command
  - a process executing out of a temp or user-writable path
  - unsigned binaries, especially combined with any of the above
  - known living-off-the-land binaries used to download files
  - svchost.exe running under the wrong parent, a classic masquerade

Each event is one JSON object:

  {"timestamp": "...", "host": "WS-104", "user": "DOMAIN\\user",
   "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
   "command_line": "powershell.exe -enc ...", "parent_image": "...",
   "signed": true, "company": "Microsoft Corporation"}

Usage:
  python3 edr_telemetry_analyzer.py sample_telemetry.json
"""

import json
import re
import sys
from pathlib import Path

OFFICE_IMAGES = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe"}
SHELL_IMAGES = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
                "mshta.exe", "rundll32.exe", "regsvr32.exe"}
DOWNLOAD_TOOL_PATTERNS = [
    (re.compile(r"certutil(\.exe)?\s+.*(-urlcache|-f\s+http)", re.I), "certutil used to download a file"),
    (re.compile(r"bitsadmin(\.exe)?\s+/transfer", re.I), "bitsadmin used to transfer a file"),
    (re.compile(r"mshta(\.exe)?\s+https?://", re.I), "mshta launching a remote script"),
    (re.compile(r"(invoke-webrequest|invoke-restmethod|net\.webclient|downloadstring)", re.I),
     "PowerShell web download cradle"),
]
ENCODED_PS = re.compile(r"-(enc|encodedcommand|e)\b", re.I)
LONG_BASE64 = re.compile(r"[A-Za-z0-9+/=]{120,}")
USER_WRITABLE = re.compile(r"\\(appdata|temp|downloads|users\\public)\\", re.I)
TEMP_PATH = re.compile(r"\\(temp|tmp)\\", re.I)


def image_name(path):
    return Path(path.replace("\\", "/")).name.lower()


def analyze_event(event):
    """Return a list of (severity, reason) alerts for one process event."""
    alerts = []
    image = image_name(event.get("image", ""))
    parent = image_name(event.get("parent_image", ""))
    cmdline = event.get("command_line", "") or ""
    image_path = event.get("image", "") or ""
    signed = event.get("signed")

    if parent in OFFICE_IMAGES and image in SHELL_IMAGES:
        alerts.append(("HIGH", f"Office application {parent} spawned {image}; documents should not launch shells"))

    if image in ("powershell.exe", "pwsh.exe") and (ENCODED_PS.search(cmdline) or LONG_BASE64.search(cmdline)):
        alerts.append(("HIGH", "PowerShell running an encoded or heavily obfuscated command"))

    for pattern, reason in DOWNLOAD_TOOL_PATTERNS:
        if pattern.search(cmdline):
            alerts.append(("MEDIUM", f"Living-off-the-land download: {reason}"))

    if TEMP_PATH.search(image_path):
        alerts.append(("MEDIUM", f"Process executing from a temp path: {image_path}"))
    elif USER_WRITABLE.search(image_path) and image not in OFFICE_IMAGES:
        alerts.append(("LOW", f"Process executing from a user-writable path: {image_path}"))

    if signed is False:
        if alerts:
            alerts.append(("MEDIUM", "Binary is unsigned, on top of the behavior above"))
        else:
            alerts.append(("LOW", "Binary is unsigned"))

    if image == "svchost.exe" and parent not in ("services.exe", ""):
        alerts.append(("MEDIUM", f"svchost.exe parent is {parent or 'unknown'}, expected services.exe; possible masquerade"))

    return alerts


def analyze(events):
    """Return (event, alerts) pairs for every event that raised at least one alert."""
    flagged = []
    for event in events:
        alerts = analyze_event(event)
        if alerts:
            flagged.append((event, alerts))
    return flagged


def severity_of(alerts):
    order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    return max(order[s] for s, _ in alerts)


def build_report(events):
    flagged = analyze(events)
    lines = []
    lines.append("EDR telemetry findings")
    lines.append("======================")
    lines.append(f"Process events reviewed: {len(events)}")
    lines.append(f"Events with alerts: {len(flagged)}")
    lines.append("")
    if not flagged:
        lines.append("No alerts. Quiet log, or the rules need work; check which before celebrating.")
        return "\n".join(lines) + "\n"
    for event, alerts in sorted(flagged, key=lambda pair: -severity_of(pair[1])):
        top = max((s for s, _ in alerts), key=lambda s: {"HIGH": 3, "MEDIUM": 2, "LOW": 1}[s])
        lines.append(f"[{top}] {event.get('timestamp', '?')} {event.get('host', '?')} user {event.get('user', '?')}")
        lines.append(f"    {event.get('parent_image', '?')} -> {event.get('image', '?')}")
        cmdline = event.get("command_line", "")
        if cmdline:
            shown = cmdline if len(cmdline) <= 140 else cmdline[:137] + "..."
            lines.append(f"    cmd: {shown}")
        for severity, reason in alerts:
            lines.append(f"    - {severity}: {reason}")
        lines.append("")
    lines.append("Note: these are behavior leads for an analyst to work, the same way an EDR")
    lines.append("console presents them. Signed and expected is not the same as safe, and")
    lines.append("unsigned is not the same as malicious; the combination is the signal.")
    return "\n".join(lines) + "\n"


def main(argv):
    if len(argv) != 2:
        print("Usage: python3 edr_telemetry_analyzer.py <telemetry.json>")
        return 1
    with open(argv[1]) as handle:
        events = json.load(handle)
    print(build_report(events), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
