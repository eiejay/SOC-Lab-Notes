#!/usr/bin/env python3
"""Analyze an email file (.eml) for phishing indicators.

Usage:
    python3 analyze_headers.py sample_phish.eml

Checks, in the order an analyst works them:
  1. Authentication results: SPF, DKIM, DMARC pass or fail
  2. From domain vs Reply-To and Return-Path domains
  3. Look-alike domain: digit substitutions against known brands
  4. Links in the body that point at raw IP addresses

Prints each finding and a final verdict. Nothing here proves phishing
on its own; the score is the sum of independent failures, which is
how a human analyst reaches the same call.
"""

import re
import sys
from email import policy
from email.parser import BytesParser

KNOWN_BRANDS = {
    "microsoft.com": "microsoft",
    "google.com": "google",
    "apple.com": "apple",
    "amazon.com": "amazon",
    "paypal.com": "paypal",
    "outlook.com": "outlook",
}

SUBSTITUTIONS = {"0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "@": "a"}


def domain_of(address_field):
    if not address_field:
        return ""
    match = re.search(r"@([A-Za-z0-9.-]+)", str(address_field))
    return match.group(1).lower().strip(">") if match else ""


def normalize(domain):
    return "".join(SUBSTITUTIONS.get(ch, ch) for ch in domain)


def auth_result(headers, key):
    for header in headers:
        match = re.search(rf"{key}=(pass|fail|none|softfail|neutral)", header.lower())
        if match:
            return match.group(1)
    return "not present"


def analyze(path):
    with open(path, "rb") as handle:
        message = BytesParser(policy=policy.default).parse(handle)

    findings = []
    auth_headers = message.get_all("Authentication-Results", [])
    for key in ("spf", "dkim", "dmarc"):
        result = auth_result(auth_headers, key)
        if result in ("fail", "none", "softfail"):
            findings.append(f"{key.upper()} result is {result}: sender authentication is weak or failing")

    from_domain = domain_of(message.get("From", ""))
    reply_domain = domain_of(message.get("Reply-To", ""))
    return_domain = domain_of(message.get("Return-Path", ""))
    if reply_domain and reply_domain != from_domain:
        findings.append(f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain}): replies leave the claimed sender")
    if return_domain and return_domain != from_domain:
        findings.append(f"Return-Path domain ({return_domain}) differs from From domain ({from_domain})")

    normalized = normalize(from_domain)
    for brand_domain, brand in KNOWN_BRANDS.items():
        if from_domain != brand_domain and brand in normalized:
            findings.append(f"From domain ({from_domain}) looks like a look-alike of {brand_domain}")

    body = ""
    if message.is_multipart():
        for part in message.walk():
            if part.get_content_type() == "text/plain":
                body += str(part.get_payload(decode=True) or b"")
    else:
        payload = message.get_payload(decode=True)
        body = payload.decode("utf-8", errors="replace") if payload else str(message.get_payload())
    ip_links = re.findall(r"https?://\d+\.\d+\.\d+\.\d+[^\s\"']*", body)
    for link in ip_links:
        findings.append(f"Link points at a raw IP address: {link}")

    print(f"From domain: {from_domain or 'unknown'}")
    print(f"Findings: {len(findings)}")
    for finding in findings:
        print(f"  - {finding}")
    if len(findings) >= 3:
        print("Verdict: LIKELY PHISHING. Three or more independent checks failed.")
    elif findings:
        print("Verdict: SUSPICIOUS. Review manually before anyone acts on this message.")
    else:
        print("Verdict: No indicators found by these checks. Absence of findings is not proof of safety.")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 analyze_headers.py <email.eml>")
        sys.exit(1)
    sys.exit(analyze(sys.argv[1]))
