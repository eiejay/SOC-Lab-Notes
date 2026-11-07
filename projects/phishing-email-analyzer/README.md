# Phishing Email Analyzer

A working header analysis tool plus the manual walkthrough behind it. The script, analyze_headers.py, reads an .eml file and runs the checks an analyst runs: authentication results, domain mismatches, look-alike domains, and IP-based links.

## Run it

    python3 analyze_headers.py sample_phish.eml

Expected result on the sample: five findings (SPF fail, DKIM none, DMARC fail, Reply-To mismatch, look-alike domain, IP link) and a LIKELY PHISHING verdict. The sample message is fictional; every address uses reserved example domains and documentation IP ranges.

## What the tool checks

1. Authentication-Results: SPF, DKIM, and DMARC. Fails and nones are findings, in that order of weight.
2. From vs Reply-To vs Return-Path domains. A reply path that leaves the claimed organization is a classic phish construction.
3. Look-alike domains: common digit substitutions (0 for o, 1 for l) are normalized and compared against known brand domains.
4. Links whose destination is a raw IP address instead of a hostname.

Three or more independent findings returns LIKELY PHISHING. One or two returns SUSPICIOUS, because a single failed check has innocent explanations and a pile of them does not.

## The manual walkthrough

The tool automates the header work. The content read stays human:

- Urgency and threat in the subject and first line: pressure is a social engineering marker, not a writing style.
- The ask: credentials, payment, or an attachment. Legitimate IT does not collect passwords by email.
- Attachment names with double extensions, such as Invoice_Q3.pdf.exe.
- Greeting and signature quality against what the real organization sends.

## Verdict and actions on a real case

1. Tell the user: do not click, do not reply. If they clicked, treat as credential exposure: reset the password and review that account's sign-in logs.
2. Search mailbox logs for the same sender and subject: who else received it?
3. Block the sender domain and destination at the gateway and proxy.
4. File the incident report with the indicators: sender domain, reply-to domain, URLs, IPs, and the attachment hash if one exists.

## Quick reference: header fields that matter

| Field | What to look for |
| --- | --- |
| Authentication-Results | spf, dkim, dmarc: pass or fail |
| From vs Reply-To | Different domains is a warning sign |
| Received chain | Does the first hop match the claimed sender? |
| Message-ID domain | Mismatch with From domain is a warning sign |
| Return-Path | Where bounces go; often the true sender |
