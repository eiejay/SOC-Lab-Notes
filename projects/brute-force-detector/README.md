# Brute Force Detector

A small Python tool that reads a Linux SSH authentication log and reports which source IP addresses show a brute force pattern: repeated failed logins above a threshold.

## Why this exists

Failed-login bursts are among the most common alerts a Tier 1 analyst touches. This script automates the first step of that triage: count the failures per source, and say plainly which sources crossed the line.

## Run it

    python3 brute_force_detector.py sample_auth.log
    python3 brute_force_detector.py sample_auth.log 3

The second number is the failure threshold (default 5). The included sample log uses documentation IP ranges (203.0.113.x, 198.51.100.x) and invented usernames; no real addresses or accounts.

## Sample output

    Source IP        Failures  Accepted  Verdict
    203.0.113.45           7         1  INVESTIGATE: failures above threshold and a success followed
    198.51.100.23          2         0  Below threshold

## How it works

1. Read the log line by line.
2. Lines containing "Failed password" add a failure to that source IP and record the target username.
3. Lines containing "Accepted password" add a success to that source IP.
4. Any source at or above the threshold is flagged. A flagged source that also has a success is marked INVESTIGATE first, because failures followed by a success is the pattern that means a password may have fallen.

## Analyst notes

- A flagged IP is a lead, not a verdict. Check whether the account owner was traveling, mistyping, or using a new device.
- In a SIEM, the same logic runs as a scheduled search; see the Splunk Detection Pack in this repository for the SPL version.
- Next improvement: time-window the counting, so slow attacks spread over days still surface.
