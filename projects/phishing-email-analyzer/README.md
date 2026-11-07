# Phishing Email Analyzer

How a suspicious email gets analyzed in a SOC: headers first, content second, verdict last. Worked end to end on one example. All addresses, domains, and IPs below are fictional and use reserved example ranges.

## The example

A user reports an email:

- From display name: IT Helpdesk
- From address: support@micros0ft-verify.example.com
- Reply-To: helpdesk-reply@secure-login.example.net
- Subject: Urgent: your password expires today
- Body: a link labeled "Sign in to keep your account" pointing to http://192.0.2.77/login, plus an attachment named Invoice_Q3.pdf.exe

## Step 1: Authentication results in the headers

    Authentication-Results: mx; spf=fail; dkim=none; dmarc=fail

- SPF fail: the sending server is not authorized for the claimed domain.
- DKIM none: no signature to verify.
- DMARC fail with a strict policy means the message should never have been delivered; its presence in the inbox is itself worth a note to the email team.

## Step 2: Address checks

- The From domain (micros0ft-verify.example.com) is a look-alike: a zero replaces the letter o, and the real organization does not own it.
- The Reply-To domain differs from the From domain, so replies leave the claimed organization entirely. Legitimate senders rarely do this.

## Step 3: Content checks

- Urgency and threat: "expires today" pressures the reader past careful thought. Classic social engineering marker.
- The link text says one thing; the destination is a raw IP address over plain HTTP. No legitimate sign-in page works that way.
- The attachment ends in .pdf.exe: a double extension hiding an executable behind a document icon.

## Step 4: Verdict and actions

Verdict: phishing, high confidence. Four independent checks failed; any two would justify the call.

Actions:

1. Tell the user: do not click, do not reply, delete after the report is filed. If they clicked, treat as a credential exposure: force a password reset and review sign-in logs for that account.
2. Search the mailbox logs for the same subject and sender: who else received it?
3. Block the sender domain and the destination IP at the email gateway and proxy.
4. File the incident report with the indicators (sender domain, reply-to domain, URL, IP, attachment hash if available).

## Quick reference: header fields that matter

| Field | What to look for |
| --- | --- |
| Authentication-Results | spf, dkim, dmarc: pass or fail |
| From vs Reply-To | Different domains is a warning sign |
| Received chain | Does the first hop match the claimed sender? |
| Message-ID domain | Mismatch with From domain is a warning sign |
| Return-Path | Where bounces go; often the true sender |
