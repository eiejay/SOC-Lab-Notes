# Proxy Log Analyzer

A small Python tool that reads a web proxy log and writes a findings report. I built it during SOC training to practice the part of proxy review that is judgment, not syntax: telling a machine checking in from a person browsing.

## What it looks for

- **Possible beaconing.** Requests are grouped by client and host. A group with five or more calls whose intervals barely vary (coefficient of variation under 0.15) reads as a machine rhythm, not a human one. Humans do not click every 300 seconds, give or take 4.
- **Large uploads.** Any POST or PUT at or over a threshold (5 MB by default) gets listed with its size. That is what data leaving the building looks like in a proxy log before anyone proves it.
- **Rare domains.** Hosts seen once or twice in the whole log. One-shot phishing pages and drive-by infrastructure live here, mixed in with harmless one-off visits, which is why the report calls them leads, not verdicts.
- **Suspicious hosts.** Cheap throwaway TLDs (.xyz, .top, .click and friends) and hostnames long enough to look generated rather than named.

## What it demonstrates

Proxy log triage and beacon detection with nothing but the standard library: parsing, grouping, and one honest statistic (interval variation) doing the heavy lifting. The sample log also contains a control case on purpose: a vendor telemetry agent that calls home six times at irregular intervals. It should not flag, and it does not. A detection that cannot tell those two apart is a noise machine.

## How to run

```bash
python3 proxy_log_analyzer.py sample_proxy.log
python3 proxy_log_analyzer.py sample_proxy.log --upload-threshold 1048576
```

Log format, one request per line:

```text
2026-11-10T08:15:23Z 192.168.1.23 jdoe GET http://example.com/ 200 5231 812 "Mozilla/5.0"
```

Fields: timestamp, client IP, user, method, URL, status, bytes downloaded, bytes uploaded, user agent. Lines that do not parse are skipped and counted in the report header.

## Sample output

From the included sample log (30 requests, one office morning):

```text
[1] Possible beaconing (1)
    192.168.1.44 -> updates-cdn.example.xyz: 6 requests, mean interval 300s, variation 0.01 (under 0.15 reads as machine rhythm)

[2] Large uploads, at or over 5242880 bytes (1)
    2026-11-10T09:47:26Z 192.168.1.58 dlee POST https://fileshare-drop.example.top/upload uploaded 8945211 bytes

[3] Rare domains, seen 2 times or fewer (5)
    ...
[4] Suspicious hosts (4)
    ...
```

The story in the sample: 192.168.1.44 beacons to a .xyz host every five minutes and later pulls a 5 MB executable, 192.168.1.58 pushes 8.9 MB out to a .top file share with curl, and 192.168.1.37 visits a .click look-alike login page and posts to it. Three separate tickets on a real shift.

## Tuning notes and limits

- The beacon thresholds are constants at the top of the script. Tighten the variation limit and real beacons with jitter slip through; loosen it and updaters start flagging. That trade-off is the job.
- Rare-domain logic needs a bigger log than this sample to mean much. On a real proxy export I would compare against a 30 day baseline instead of a flat count.
- The TLD list is a short starter set, not a threat intel feed.
