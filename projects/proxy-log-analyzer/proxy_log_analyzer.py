"""Proxy log analyzer.

Reads a web proxy log and writes a findings report. It looks for the four
patterns I kept coming back to in training when a proxy log was put in
front of me:

  - possible beaconing: one client calling the same domain at suspiciously
    regular intervals, the way malware checks in for instructions
  - large uploads to outside domains, which is what exfiltration looks
    like before anyone confirms it
  - rare domains: a host touched once or twice in the whole log, which is
    where drive-by and one-shot phishing infrastructure hides
  - suspicious top level domains and very long hostnames, both common in
    throwaway attacker infrastructure

Log format (one request per line, space separated, user agent quoted):

  2026-11-10T08:15:23Z 192.168.1.23 jdoe GET http://example.com/ 200 5231 812 "Mozilla/5.0"

Fields: timestamp, client IP, user, method, URL, status,
bytes sent to the client (download), bytes received from the client
(upload), user agent.

Usage:
  python3 proxy_log_analyzer.py sample_proxy.log
  python3 proxy_log_analyzer.py sample_proxy.log --upload-threshold 1048576
"""

import re
import statistics
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from urllib.parse import urlparse

LINE_RE = re.compile(
    r'^(?P<ts>\S+) (?P<client>\S+) (?P<user>\S+) (?P<method>[A-Z]+) '
    r'(?P<url>\S+) (?P<status>\d{3}) (?P<down>\d+) (?P<up>\d+) "(?P<ua>[^"]*)"$'
)

# Throwaway infrastructure loves cheap or free TLDs. This is a short,
# deliberately conservative list, not a blocklist.
SUSPICIOUS_TLDS = {".xyz", ".top", ".click", ".work", ".zip", ".mov", ".gq", ".tk", ".buzz", ".rest"}

DEFAULT_UPLOAD_THRESHOLD = 5 * 1024 * 1024  # 5 MB in one request
RARE_DOMAIN_MAX = 2          # a domain seen this many times or fewer is rare
BEACON_MIN_HITS = 5          # need at least this many calls to judge rhythm
BEACON_MAX_CV = 0.15         # coefficient of variation: under this is "too regular"
BEACON_MIN_MEAN = 30         # seconds; faster than this is just a busy app
BEACON_MAX_MEAN = 7200       # seconds; slower than this is not a check-in rhythm


def parse_log(path):
    """Parse the proxy log into a list of request dicts. Bad lines are skipped and counted."""
    requests = []
    skipped = 0
    with open(path) as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = LINE_RE.match(line)
            if not match:
                skipped += 1
                continue
            entry = match.groupdict()
            entry["time"] = datetime.strptime(entry["ts"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            entry["down"] = int(entry["down"])
            entry["up"] = int(entry["up"])
            entry["host"] = urlparse(entry["url"]).hostname or ""
            requests.append(entry)
    return requests, skipped


def find_beacons(requests):
    """Group by client and host; flag groups whose call rhythm is too regular to be a human."""
    groups = defaultdict(list)
    for req in requests:
        groups[(req["client"], req["host"])].append(req["time"])
    findings = []
    for (client, host), times in sorted(groups.items()):
        if len(times) < BEACON_MIN_HITS:
            continue
        times.sort()
        intervals = [(b - a).total_seconds() for a, b in zip(times, times[1:])]
        if not intervals or min(intervals) <= 0:
            continue
        mean = statistics.mean(intervals)
        cv = statistics.pstdev(intervals) / mean if mean else 0
        if BEACON_MIN_MEAN <= mean <= BEACON_MAX_MEAN and cv <= BEACON_MAX_CV:
            findings.append({
                "client": client, "host": host, "hits": len(times),
                "mean_interval": mean, "cv": cv,
            })
    return findings


def find_large_uploads(requests, threshold):
    """POST or PUT requests that pushed more than the threshold out to one host."""
    findings = []
    for req in requests:
        if req["method"] in ("POST", "PUT") and req["up"] >= threshold:
            findings.append(req)
    return findings


def find_rare_domains(requests):
    """Domains seen at most RARE_DOMAIN_MAX times across the whole log."""
    counts = Counter(req["host"] for req in requests)
    rare = {host: n for host, n in counts.items() if n <= RARE_DOMAIN_MAX}
    examples = {}
    for req in requests:
        if req["host"] in rare and req["host"] not in examples:
            examples[req["host"]] = req
    return rare, examples


def find_suspicious_hosts(requests):
    """Hosts on a suspicious TLD, or with a hostname long enough to smell generated."""
    seen = {}
    for req in requests:
        host = req["host"]
        if host in seen:
            continue
        reasons = []
        for tld in SUSPICIOUS_TLDS:
            if host.endswith(tld):
                reasons.append(f"suspicious TLD {tld}")
        if len(host) >= 40:
            reasons.append(f"long hostname ({len(host)} chars)")
        leftmost = host.split(".")[0]
        if len(leftmost) >= 25:
            reasons.append(f"long leftmost label ({len(leftmost)} chars), possibly generated")
        if reasons:
            seen[host] = {"client": req["client"], "reasons": reasons}
    return seen


def build_report(requests, skipped, upload_threshold):
    lines = []
    lines.append("Proxy log findings report")
    lines.append("=========================")
    lines.append(f"Requests parsed: {len(requests)} (skipped lines: {skipped})")
    clients = {req['client'] for req in requests}
    hosts = {req['host'] for req in requests}
    lines.append(f"Clients: {len(clients)}  Unique hosts: {len(hosts)}")
    lines.append("")

    beacons = find_beacons(requests)
    lines.append(f"[1] Possible beaconing ({len(beacons)})")
    if not beacons:
        lines.append("    none")
    for b in beacons:
        lines.append(
            f"    {b['client']} -> {b['host']}: {b['hits']} requests, "
            f"mean interval {b['mean_interval']:.0f}s, variation {b['cv']:.2f} (under {BEACON_MAX_CV} reads as machine rhythm)"
        )
    lines.append("")

    uploads = find_large_uploads(requests, upload_threshold)
    lines.append(f"[2] Large uploads, at or over {upload_threshold} bytes ({len(uploads)})")
    if not uploads:
        lines.append("    none")
    for req in uploads:
        lines.append(
            f"    {req['ts']} {req['client']} {req['user']} {req['method']} {req['url']} "
            f"uploaded {req['up']} bytes"
        )
    lines.append("")

    rare, examples = find_rare_domains(requests)
    lines.append(f"[3] Rare domains, seen {RARE_DOMAIN_MAX} times or fewer ({len(rare)})")
    if not rare:
        lines.append("    none")
    for host in sorted(rare):
        req = examples[host]
        lines.append(f"    {host} x{rare[host]} (first seen {req['ts']} from {req['client']})")
    lines.append("")

    suspicious = find_suspicious_hosts(requests)
    lines.append(f"[4] Suspicious hosts ({len(suspicious)})")
    if not suspicious:
        lines.append("    none")
    for host in sorted(suspicious):
        info = suspicious[host]
        lines.append(f"    {host} (from {info['client']}): {'; '.join(info['reasons'])}")
    lines.append("")
    lines.append("Note: findings are leads for triage, not verdicts. Rare is not the same as malicious,")
    lines.append("and a regular rhythm can be a software updater. Context decides.")
    return "\n".join(lines) + "\n"


def main(argv):
    args = [a for a in argv[1:] if not a.startswith("--")]
    threshold = DEFAULT_UPLOAD_THRESHOLD
    if "--upload-threshold" in argv:
        idx = argv.index("--upload-threshold")
        threshold = int(argv[idx + 1])
        args = [a for a in args if a != argv[idx + 1]]
    if len(args) != 1:
        print("Usage: python3 proxy_log_analyzer.py <proxy.log> [--upload-threshold BYTES]")
        return 1
    requests, skipped = parse_log(args[0])
    print(build_report(requests, skipped, threshold), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
