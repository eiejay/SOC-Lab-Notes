"""Email header analyzer.

Parses a saved email (.eml) and works the header the way a phishing
ticket gets worked: authentication first, then alignment, then the
tricks that live in the display name and the Reply-To.

Checks:
  - SPF, DKIM and DMARC results from the Authentication-Results header
  - alignment: does the Return-Path domain match the From domain, and
    does the DKIM signing domain match the From domain
  - display name spoofing: a brand name in the display name that the
    sending domain has no claim to, or an email address written into
    the display name that is not the real sending address
  - Reply-To on a different domain than From, where replies (and
    victims) get redirected
  - Received chain sanity: no Received headers at all is a forgery
    smell, and the chain is counted so an analyst can eyeball the hops

The verdict is a risk score with every reason printed. A score is a
triage shortcut, not a judgment; the reasons are the judgment.

Usage:
  python3 email_header_analyzer.py samples/phishing.eml
"""

import re
import sys
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr

# Brands that phishers put in display names. Small on purpose: this is
# the display name trick, not a threat intel service.
BRANDS = ["paypal", "microsoft", "apple", "amazon", "google", "chase",
          "bank of america", "wells fargo", "netflix", "irs", "outlook"]

EMAIL_IN_TEXT = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")


def domain_of(address):
    return address.rsplit("@", 1)[-1].strip().lower() if "@" in address else ""


def registrable(domain):
    """Last two labels, good enough for alignment checks in a lab tool."""
    parts = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def auth_results(msg):
    """Pull spf/dkim/dmarc verdicts out of Authentication-Results, if present."""
    header = msg.get("Authentication-Results", "") or ""
    results = {}
    for mechanism in ("spf", "dkim", "dmarc"):
        match = re.search(mechanism + r"=(pass|fail|none|neutral|softfail)", header, re.I)
        results[mechanism] = match.group(1).lower() if match else "absent"
    dkim_domain = re.search(r"header\.i=@([\w.-]+)", header, re.I)
    results["dkim_domain"] = dkim_domain.group(1).lower() if dkim_domain else ""
    return results


def analyze(path):
    """Return (score, findings) where findings is a list of (points, text)."""
    with open(path, "rb") as handle:
        msg = BytesParser(policy=policy.default).parse(handle)

    findings = []
    score = 0

    def add(points, text):
        nonlocal score
        score += points
        findings.append((points, text))

    from_name, from_addr = parseaddr(str(msg.get("From", "")))
    from_domain = domain_of(from_addr)
    from_reg = registrable(from_domain)

    auth = auth_results(msg)
    if auth["spf"] == "fail":
        add(3, "SPF failed: the sending server is not authorized for this domain")
    elif auth["spf"] in ("softfail", "neutral"):
        add(1, f"SPF result is {auth['spf']}, a weak pass at best")
    elif auth["spf"] == "absent":
        add(1, "No SPF result recorded in Authentication-Results")

    if auth["dkim"] == "fail":
        add(3, "DKIM failed: the signature does not verify")
    elif auth["dkim"] in ("none", "absent"):
        add(1, "Message is not DKIM signed")

    if auth["dmarc"] == "fail":
        add(3, "DMARC failed: the message does not align with the From domain's policy")
    elif auth["dmarc"] in ("none", "absent"):
        add(1, "No DMARC result recorded; the From domain may have no DMARC policy")

    return_path = parseaddr(str(msg.get("Return-Path", "")))[1]
    rp_domain = domain_of(return_path)
    if rp_domain and from_domain and registrable(rp_domain) != from_reg:
        add(2, f"Return-Path domain {rp_domain} does not align with From domain {from_domain}")

    if auth["dkim_domain"] and from_domain and registrable(auth["dkim_domain"]) != from_reg:
        add(2, f"DKIM signing domain {auth['dkim_domain']} does not align with From domain {from_domain}")

    if from_name:
        lowered = from_name.lower()
        for brand in BRANDS:
            if brand in lowered and brand.replace(" ", "") not in from_domain.replace("-", ""):
                add(3, f"Display name claims '{from_name}' but the sending domain is {from_domain}")
                break
        shown = EMAIL_IN_TEXT.search(from_name)
        if shown and shown.group(0).lower() != from_addr.lower():
            add(3, f"Display name shows address {shown.group(0)} but the real sender is {from_addr}")

    reply_to = parseaddr(str(msg.get("Reply-To", "")))[1]
    rt_domain = domain_of(reply_to)
    if rt_domain and from_domain and registrable(rt_domain) != from_reg:
        add(1, f"Reply-To domain {rt_domain} differs from From domain {from_domain}; replies go elsewhere")

    received = msg.get_all("Received", []) or []
    if len(received) == 0:
        add(2, "No Received headers at all; a real message leaves a chain")
    return score, findings, {
        "from": str(msg.get("From", "")),
        "subject": str(msg.get("Subject", "")),
        "auth": auth,
        "received_hops": len(received),
    }


def verdict_for(score):
    if score >= 5:
        return "HIGH RISK - treat as phishing until proven otherwise"
    if score >= 2:
        return "SUSPICIOUS - work it before anyone clicks anything"
    return "LOW RISK - authentication and alignment look sound"


def build_report(path):
    score, findings, info = analyze(path)
    lines = []
    lines.append(f"Email header analysis: {path}")
    lines.append("=" * 60)
    lines.append(f"From:    {info['from']}")
    lines.append(f"Subject: {info['subject']}")
    auth = info["auth"]
    lines.append(f"Auth:    SPF={auth['spf']}  DKIM={auth['dkim']}  DMARC={auth['dmarc']}")
    lines.append(f"Received hops: {info['received_hops']}")
    lines.append("")
    if findings:
        lines.append("Findings:")
        for points, text in sorted(findings, key=lambda f: -f[0]):
            lines.append(f"    (+{points}) {text}")
    else:
        lines.append("Findings: none")
    lines.append("")
    lines.append(f"Risk score: {score}")
    lines.append(f"Verdict: {verdict_for(score)}")
    return "\n".join(lines) + "\n"


def main(argv):
    if len(argv) != 2:
        print("Usage: python3 email_header_analyzer.py <message.eml>")
        return 1
    print(build_report(argv[1]), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
