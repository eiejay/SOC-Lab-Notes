# Log Analysis Notes

Reading logs during triage: what to look for, and where.

## Windows authentication events

- 4624: successful logon. Check the logon type: type 3 is network, type 10 is remote desktop.
- 4625: failed logon. A burst of 4625 events against one account is the classic brute force pattern.
- 4672: special privileges assigned at logon. Note when an admin-level account logs on, and from where.
- 4688: process creation. With command line logging, this shows exactly what ran.

Pattern to catch: many 4625 failures followed by one 4624 success on the same account means the password probably fell. Treat as a true positive until proven otherwise.

## Linux authentication logs

- /var/log/auth.log or /var/log/secure: look for Accepted and Failed password lines.
- Repeated failures from one source IP, then an acceptance, is the same brute force story as Windows.
- sudo lines show privilege use after logon.

## Network logs

- DNS: a host querying a newly seen or algorithm-generated domain is a common malware callback sign.
- Proxy: long URLs, rare user agents, and large uploads to unknown sites deserve a second look.
- Firewall: denied outbound traffic from a workstation to an unusual port often means something on the box is trying to phone home.

## Splunk search basics

Count failures by source, to find the loudest attacker:

    index=windows EventCode=4625 | stats count by src_ip

Successful logons for one account across a day:

    index=windows EventCode=4624 Account_Name=<user> | table _time, src_ip, Logon_Type

Failed then successful, the brute force check:

    index=windows (EventCode=4625 OR EventCode=4624) Account_Name=<user> | stats count by EventCode

## Working rule

One log source tells a story. Two agreeing sources tell the truth. Never close an alert on a single source when a second source is available.
