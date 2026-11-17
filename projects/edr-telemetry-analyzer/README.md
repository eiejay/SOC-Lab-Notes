# EDR Telemetry Analyzer

Reads endpoint process creation events (Sysmon style, as JSON) and raises alerts on suspicious process behavior: the same parent-child and command line patterns an EDR console is built around. I wrote it during training to learn endpoint detection from the telemetry up, instead of treating the EDR as a box that beeps.

## What it flags

- **Office spawning a shell.** Word, Excel, PowerPoint, Outlook or Access launching cmd, PowerShell, wscript, mshta, rundll32 or regsvr32. Documents do not need shells; macros do.
- **Encoded PowerShell.** The -enc / -EncodedCommand flags, or a long base64 blob in the command line.
- **Living off the land downloads.** certutil -urlcache, bitsadmin /transfer, mshta pointed at a URL, and PowerShell download cradles (DownloadString, Invoke-WebRequest and friends).
- **Execution from temp paths**, and at lower severity from other user-writable paths like AppData.
- **Unsigned binaries**, raised a step when the binary is already misbehaving. Unsigned alone is common and usually innocent; unsigned plus a temp path plus a strange parent is a story.
- **svchost.exe with the wrong parent.** Real svchost is a child of services.exe. One running out of a temp folder under a random parent is wearing the name as a costume.

## What it demonstrates

Endpoint detection logic in plain Python: process tree reasoning (who spawned whom matters more than what ran), command line inspection, and severity that comes from combinations rather than any single fact. The sample data makes the point twice: the attack chain on WS-104 lights up at every step, while a signed Teams updater running from AppData earns only a LOW, because that is what legitimate software updating itself looks like.

## Input format

A JSON list of process events:

```json
{"timestamp": "2026-11-08T09:04:37Z", "host": "WS-104", "user": "CORP\\jdoe",
 "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
 "command_line": "powershell.exe -enc ...",
 "parent_image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
 "signed": true, "company": "Microsoft Corporation"}
```

## How to run

```bash
python3 edr_telemetry_analyzer.py sample_telemetry.json
```

## Sample output

Abridged from the included sample (11 events, 6 with alerts):

```text
[HIGH] 2026-11-08T09:04:37Z WS-104 user CORP\jdoe
    C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE -> C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
    - HIGH: Office application winword.exe spawned powershell.exe; documents should not launch shells
    - HIGH: PowerShell running an encoded or heavily obfuscated command

[MEDIUM] 2026-11-08T09:07:15Z WS-104 user CORP\jdoe
    ...\invoicehelper.exe -> C:\Users\jdoe\AppData\Local\Temp\svchost.exe
    - MEDIUM: Process executing from a temp path
    - MEDIUM: Binary is unsigned, on top of the behavior above
    - MEDIUM: svchost.exe parent is invoicehelper.exe, expected services.exe; possible masquerade

[LOW] 2026-11-08T09:11:44Z WS-107 user CORP\asmith
    Teams.exe -> Update.exe (signed, from AppData)
    - LOW: Process executing from a user-writable path
```

Read top to bottom, the WS-104 alerts are one incident: malicious document, encoded PowerShell, unsigned helper dropped in Temp, certutil pulling a second payload, and a fake svchost for cover. That chain is the same one the kill-chain-mapper project maps to ATT&CK and the Cyber Kill Chain.

## Limits

- Rules only, no baselining. A real EDR learns what a given host normally runs; this tool knows generic bad behavior and generic good behavior and nothing about your environment.
- Only process creation is covered. Registry, file, and network events (the rest of Sysmon) would each earn their own rules, and correlating them is where real detections get strong.
