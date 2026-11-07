# Alert Triage Workflow

The process used when a new alert lands in the queue.

## 1. Receive and acknowledge

- Note the alert time, the source tool, and the alert name.
- Acknowledge the alert so the team knows it is being worked.

## 2. Validate: is it a true positive?

- Identify the asset: server, workstation, or user account involved.
- Check the context: is this activity expected for this user or system?
- Look for a benign explanation first (software update, admin task, vulnerability scan) before treating it as hostile.

## 3. Prioritize

Severity is impact times confidence:

- High impact: production server, domain controller, executive or privileged account
- High confidence: multiple data sources agree, known-bad indicator, clear pattern

## 4. Investigate

Pull the surrounding logs before deciding:

- Authentication logs for the account (success and failure patterns)
- DNS and proxy logs for the host (where did it connect?)
- Endpoint data (process tree, file changes)
- Email gateway data if the alert involves a message or attachment

## 5. Decide and act

- True positive: contain per playbook (isolate host, disable account, block indicator) and escalate to Tier 2 with notes.
- False positive: close with the reason documented, and note if the detection rule needs tuning.
- Unclear: escalate rather than guess. An escalation with good notes is never wrong.

## 6. Document and hand off

Every alert, closed or escalated, gets:

- What fired, and when
- What was checked
- What was found
- What was done
- What the next analyst should watch for
