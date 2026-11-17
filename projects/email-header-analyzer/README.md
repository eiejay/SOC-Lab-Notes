# Email Header Analyzer

Parses a saved email (.eml) and works the headers the way a phishing ticket gets worked: authentication first, alignment second, and then the tricks that live in the display name and the Reply-To. It prints every reason it found and a risk score at the end.

This is the header forensics companion to the phishing-email-analyzer elsewhere in this repo. That tool scores a whole message including its links and body habits. This one stays in the headers, because on a real ticket the headers are where a spoof proves itself.

## What it checks

- **SPF, DKIM, DMARC** results, read out of the Authentication-Results header the receiving server stamped on the message.
- **Alignment.** DMARC is not just pass or fail; it is about whether the domains line up. The tool compares the Return-Path domain and the DKIM signing domain against the From domain the user actually sees.
- **Display name spoofing.** Two flavors: a brand name (PayPal, Microsoft, a bank) in the display name while the sending domain has no claim to that brand, and an email address written into the display name that is not the address the mail really came from. Both are cheap tricks and both work on tired people.
- **Reply-To redirection.** A Reply-To on a different domain means the conversation, and any credentials or wires discussed in it, go somewhere the From address never mentioned.
- **Received chain sanity.** Every real message accumulates Received headers as it crosses servers. None at all is a forgery smell, and the hop count is printed so an analyst can eyeball the path.

## What it demonstrates

Header level email authentication the way it is actually practiced: parsing with the standard library email package, reading Authentication-Results instead of guessing, and understanding alignment, which is the part of DMARC that catches spoofs even when SPF or DKIM pass on the wrong domain. The scoring is deliberately transparent: every point is printed with its reason, because a verdict you cannot explain is a verdict you cannot defend on a ticket.

## How to run

```bash
python3 email_header_analyzer.py samples/phishing.eml
python3 email_header_analyzer.py samples/legitimate.eml
python3 email_header_analyzer.py samples/suspicious.eml
```

## Sample output

The phishing sample, which fails nearly everything a header can fail:

```text
From:    PayPal Account Team <service@paypa1-secure.example>
Auth:    SPF=fail  DKIM=none  DMARC=fail
Received hops: 1

Findings:
    (+3) SPF failed: the sending server is not authorized for this domain
    (+3) DMARC failed: the message does not align with the From domain's policy
    (+3) Display name claims 'PayPal Account Team' but the sending domain is paypa1-secure.example
    (+2) Return-Path domain mailer-relay-example.net does not align with From domain paypa1-secure.example
    (+1) Message is not DKIM signed
    (+1) Reply-To domain account-helpdesk-example.org differs from From domain paypa1-secure.example; replies go elsewhere

Risk score: 13
Verdict: HIGH RISK - treat as phishing until proven otherwise
```

The three samples are a set on purpose: a genuine Google alert that scores 0, a real-looking marketing mail that scores 2 (no DMARC, replies routed to a different mailer - common, sloppy, worth a look), and the phish at 13. Telling those three apart is the whole skill.

## Limits

- The tool trusts the Authentication-Results header on the saved message. That is correct for mail your own server received and stamped; a hand-crafted .eml can lie, which is why analysts verify against the raw message from the mail gateway.
- The brand list is short and the alignment check uses the last two domain labels, so domains under multi-part public suffixes (co.uk style) are approximated. Both are noted in the code where they live.
