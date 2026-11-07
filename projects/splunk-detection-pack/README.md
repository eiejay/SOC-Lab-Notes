# Splunk Detection Pack

Five Splunk detections for common Tier 1 work. Each search lives in its own file under searches/ so it can be lifted straight into a Splunk environment, and each is documented here with purpose, meaning, and tuning. Field names follow common Windows and network log conventions; adapt index and sourcetype names to the local environment.

## 1. brute_force.spl: repeated failed logons, one source

Catches password guessing against Windows accounts: ten or more 4625 failures in fifteen minutes from one source. On a hit, check whether a success followed for the same account. Tune: raise the threshold for service accounts with known bad passwords; alert lower for privileged accounts.

## 2. failures_then_success.spl: the guess that worked

The dangerous half of brute force: five or more failures and at least one success for the same account and source in an hour. This is a priority investigation, not a routine alert: verify with the account owner first. Tune: exclude known jump hosts.

## 3. dns_beaconing.spl: regular low-volume DNS to one rare domain

Malware callbacks repeat on a timer. This search finds hosts querying one domain at steady intervals across a day. Tune: whitelist software update and telemetry domains, which beacon legitimately.

## 4. privilege_escalation.spl: account added to administrators

Event 4732 records a member added to a security-enabled local group. Every hit should map to an approved change ticket. No ticket, escalate. Low volume, high signal; no tuning needed.

## 5. after_hours_logon.spl: remote logons while the business sleeps

Remote desktop logons overnight, worth a look especially when paired with any other alert on the same account. Tune: maintain the on-call and shift-worker list; expect hits during maintenance windows.

## Working notes

- Every detection ships with tuning notes because a detection that cries wolf gets ignored, and an ignored detection is worse than none.
- Document false positives in the incident notes; patterns there are the tuning backlog.
- The brute force logic also exists as a Python tool in this repository (projects/brute-force-detector), so the same detection can be explained two ways: as a search and as code.
