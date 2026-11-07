# Walkthrough

A guided tour of the three projects in this repository: what to run, what you should see, and how to make each one yours. Everything below uses the included sample data, so it works exactly as written.

## Before you start

You need Python 3 (any recent version) and this repository:

    git clone https://github.com/eiejay/SOC-Lab-Notes.git
    cd SOC-Lab-Notes

No packages to install. Every tool uses only the Python standard library.

## 1. Brute Force Detector

    cd projects/brute-force-detector
    python3 brute_force_detector.py sample_auth.log

What you should see:

    Source IP        Failures  Accepted  Verdict
    192.0.2.14                0         1  Below threshold
    192.0.2.51                0         1  Below threshold
    198.51.100.23             2         1  Below threshold
                      Targeted accounts: mlopez
    203.0.113.45              7         1  INVESTIGATE: failures above threshold and a success followed
                      Targeted accounts: admin, jsmith, oracle, root
    203.0.113.99              3         0  Below threshold
                      Targeted accounts: guest, test

Read it like an analyst: one source (203.0.113.45) hammered four accounts and then got in. That is the alert you would escalate. The two-failure source with a success after it is the classic fat-finger pattern: worth a note, not an escalation.

Try it: lower the threshold to 3 and watch 203.0.113.99 get flagged:

    python3 brute_force_detector.py sample_auth.log 3

Make it yours: point it at any sshd auth log (on Debian and Ubuntu, /var/log/auth.log). The parser keys on the words Failed password and Accepted password and the from IP on the same line.

## 2. Phishing Email Analyzer

    cd ../phishing-email-analyzer
    python3 analyze_headers.py sample_phish.eml

What you should see:

    From domain: micros0ft-verify.example.com
    Findings: 7
      - SPF result is fail: sender authentication is weak or failing
      - DKIM result is none: sender authentication is weak or failing
      - DMARC result is fail: sender authentication is weak or failing
      - Reply-To domain (secure-login.example.net) differs from From domain (micros0ft-verify.example.com): replies leave the claimed sender
      - Return-Path domain (secure-login.example.net) differs from From domain (micros0ft-verify.example.com)
      - From domain (micros0ft-verify.example.com) looks like a look-alike of microsoft.com
      - Link points at a raw IP address: http://192.0.2.77/login
    Verdict: LIKELY PHISHING. Three or more independent checks failed.

Make it yours: in most mail clients you can save or export a message as an .eml file (in Outlook, File, Save As; in Gmail, Show original, then Download). Run any reported phish through the tool before you answer the user who sent it to you.

## 3. Splunk Detection Pack

The searches in projects/splunk-detection-pack/searches are plain text .spl files. To use one:

1. Open the .spl file and copy the search.
2. In Splunk, paste it into the search bar. Adjust the index names (windows, dns) to your environment.
3. Read the tuning notes in that project's README before scheduling anything. A detection you have not tuned is a noise machine.

If you do not have Splunk, the free Splunk Enterprise trial or Splunk's training environments run all five searches as written against Windows event data.

## The thread through all three

The same brute force pattern appears three times: as Python (project 1), as a Splunk search (detection pack, searches 1 and 2), and as the worked pattern in the log analysis notes. That is deliberate. A Tier 1 analyst meets the same five attacks every week; the skill is recognizing them in whatever tool is in front of you.
