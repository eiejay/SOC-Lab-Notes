#!/usr/bin/env python3
"""Brute force detector for Linux SSH authentication logs.

Usage:
    python3 brute_force_detector.py <logfile> [threshold]

Reads sshd log lines, counts failed and accepted logins per source IP,
and flags sources at or above the failure threshold. A flagged source
with a successful login after failures is marked INVESTIGATE, because
that pattern can mean a password was guessed correctly.
"""

import re
import sys
from collections import defaultdict

IP_PATTERN = re.compile(r"from (\d+\.\d+\.\d+\.\d+)")
USER_PATTERN = re.compile(r"for (?:invalid user )?(\S+) from")


def analyze(path, threshold):
    failures = defaultdict(int)
    accepted = defaultdict(int)
    targets = defaultdict(set)
    with open(path, "r", errors="replace") as handle:
        for line in handle:
            ip_match = IP_PATTERN.search(line)
            if not ip_match:
                continue
            ip = ip_match.group(1)
            if "Failed password" in line:
                failures[ip] += 1
                user_match = USER_PATTERN.search(line)
                if user_match:
                    targets[ip].add(user_match.group(1))
            elif "Accepted password" in line:
                accepted[ip] += 1
    return failures, accepted, targets


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 brute_force_detector.py <logfile> [threshold]")
        return 1
    path = sys.argv[1]
    threshold = int(sys.argv[2]) if len(sys.argv) > 2 else 5
    failures, accepted, targets = analyze(path, threshold)
    print(f"{'Source IP':<18}{'Failures':>9}{'Accepted':>10}  Verdict")
    for ip in sorted(set(failures) | set(accepted)):
        fails = failures.get(ip, 0)
        ok = accepted.get(ip, 0)
        if fails >= threshold and ok > 0:
            verdict = "INVESTIGATE: failures above threshold and a success followed"
        elif fails >= threshold:
            verdict = "FLAG: failures above threshold"
        else:
            verdict = "Below threshold"
        print(f"{ip:<18}{fails:>9}{ok:>10}  {verdict}")
        if targets.get(ip):
            print(f"{'':<18}Targeted accounts: {', '.join(sorted(targets[ip]))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
