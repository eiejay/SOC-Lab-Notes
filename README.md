# SOC Lab Notes

My working notebook from the lab bench, built up while training for Tier 1 SOC work: the triage workflow I follow, the documents I reach for, and four small tools I built to understand detection from the inside instead of just reading about it. Two of them are plain Python. One is a Splunk detection pack. One is a machine learning model I trained myself, small enough to explain line by line, which was the point.

## The tools

- projects/brute-force-detector: reads an sshd auth log and flags the one pattern that matters, repeated failures followed by a success from the same source. I ran it against the sample log until the verdicts matched what my eyes said.
- projects/phishing-email-analyzer: scores a saved email the way I was taught to work a phish ticket: SPF, DKIM, DMARC, Reply-To tricks, look-alike domains, raw IP links. Seven findings on the included sample, and I can walk through every one.
- projects/phishing-ml-classifier: my first Naive Bayes model. It learns phish from legit out of 26 labeled messages and earns an honest 71 percent on messages it never saw. Rules catch yesterday's phish; I wanted to feel where learning starts to beat rules, and where it does not.
- projects/splunk-detection-pack: five searches I would actually schedule: brute force, failures then success, DNS beaconing, privilege escalation, after hours logon, each with the tuning notes that keep a detection from becoming a noise machine.

## The documents

- triage-workflow.md: how I work an alert in the first fifteen minutes, and the questions I answer before I escalate or close.
- incident-report-template.md: the report shape I fill in while the incident is warm, not after.
- log-analysis-notes.md: worked examples from auth logs, including the brute force pattern the detector automates.

## How I use this repo

WALKTHROUGH.md runs every tool against its sample data with the real output, so anyone can reproduce what I claim in about five minutes. If I cannot run it in front of you, I do not list it as a skill.

## License

MIT. The tools are small and the ideas are standard practice; take what helps.
