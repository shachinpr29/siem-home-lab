## Detection: Local Account Creation via net.exe

**MITRE ATT&CK:** T1136.001 - Create Account: Local Account
**Severity:** High
**Author:** Shachin P R
**Date:** 2026-06-27

### What it detects
Execution of net.exe or net1.exe with 'user' and '/add' arguments,
indicating a local user account was created via command line.

### SPL Query
index="main"
| rex field=_raw "<EventID>(?<EventCode>\d+)</EventID>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| rex field=_raw "<Data Name='User'>(?<User>[^<]+)</Data>"
| where EventCode="1"
| search CommandLine="*net*user*add*"
| search NOT CommandLine="*SplunkForwarder*"
| search NOT CommandLine="*localgroup*"
| table _time, User, CommandLine

### True Positive Example
Target\shach ran: net.exe user ThreatActor /add
Timestamp: 2026-06-26 12:09:35

### False Positives identified
- Splunk Forwarder installer runs net.exe to add itself to
  Performance Monitor Users group — excluded via localgroup filter

### Blind Spots / What this misses
- Account creation via PowerShell New-LocalUser cmdlet
- Account creation via Windows API directly (no net.exe involved)
- GUI-based account creation (Computer Management)

### Recommended response
1. Identify the user who ran the command (SubjectUserName)
2. Check if the account name looks like a service account or human account
3. Verify with the machine owner if the creation was authorized
4. If unauthorized — disable the created account immediately, escalate
