# Splunk Detection Pack

Five documented Splunk searches for common Tier 1 detections. Each entry gives the purpose, the SPL, what a hit means, and how to tune it. Field names follow common Windows and network log conventions; adapt index and sourcetype names to the local environment.

## 1. Brute force: repeated failed logons, one source

Purpose: catch password guessing against Windows accounts.

    index=windows EventCode=4625 earliest=-15m
    | stats count by src_ip, Account_Name
    | where count >= 10

A hit means one source failed ten or more logons in fifteen minutes. Check whether a success (4624) followed for the same account. Tune: raise the threshold for service accounts with known bad passwords, and alert on lower counts for privileged accounts.

## 2. Failures followed by success, same account

Purpose: the dangerous half of brute force: the guess that worked.

    index=windows (EventCode=4625 OR EventCode=4624) earliest=-1h
    | stats values(EventCode) as codes, count(eval(EventCode=4625)) as fails by Account_Name, src_ip
    | where fails >= 5 AND mvfind(codes, "4624") >= 0

A hit is a priority investigation, not a routine alert: verify with the account owner before anything else. Tune: exclude known jump hosts.

## 3. Possible beaconing: regular low-volume DNS to one rare domain

Purpose: malware callbacks often repeat on a timer.

    index=dns earliest=-24h
    | bin _time span=5m
    | stats count by src, query
    | where count > 20
    | stats dc(_time) as intervals, sum(count) as total by src, query
    | where intervals > 10

A host querying one uncommon domain at steady intervals for hours deserves endpoint inspection. Tune: whitelist software update and telemetry domains, which beacon legitimately.

## 4. Privilege escalation: account added to administrators

Purpose: catching an attacker (or a mistake) granting admin rights.

    index=windows EventCode=4732 earliest=-24h
    | table _time, Account_Name, TargetUserName, Group_Name

Event 4732 records a member added to a security-enabled local group. Every hit should map to an approved change ticket. No ticket, escalate. Tune: none needed; this should be a low-volume, high-signal alert.

## 5. After-hours logon by a standard user

Purpose: accounts active when the business is not.

    index=windows EventCode=4624 Logon_Type=10 earliest=-24h
    | eval hour = strftime(_time, "%H")
    | where hour < 5 OR hour > 23
    | table _time, Account_Name, src_ip

Remote desktop logons overnight are worth a look, especially paired with any other alert on the same account. Tune: maintain the on-call and shift-worker list, and expect hits during maintenance windows.

## Working notes

- Every detection ships with its tuning notes because a detection that cries wolf gets ignored, and an ignored detection is worse than none.
- Document false positives in the incident notes; patterns there are the tuning backlog.
