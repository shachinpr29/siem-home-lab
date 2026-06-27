## Detection: Recon Command Chain

**MITRE ATT&CK:** T1033 - System Owner/User Discovery | T1069.001 - Local Groups Discovery  
**Severity:** Medium  
**Author:** Shachin P R
**Date:** 2026-06-27  

### What it detects
A chain of 3 or more reconnaissance commands executed by the same user
on the same machine within a 15-minute window. Single recon commands
are treated as noise — the chain is the signal.

### Why chaining matters
Any admin can run whoami once. An attacker who just landed on a machine
runs whoami, systeminfo, net user, and net localgroup in rapid succession
to understand their environment. Frequency + variety = suspicion.

### SPL Query
```spl
index="main" earliest=-15m
| rex field=_raw "<EventID>(?<EventCode>\d+)</EventID>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| rex field=_raw "<Data Name='User'>(?<User>[^<]+)</Data>"
| rex field=_raw "<Computer>(?<Computer>[^<]+)</Computer>"
| where EventCode="1"
| eval recon=if(match(CommandLine,"whoami|net user|net localgroup|systeminfo|ipconfig|hostname"),1,0)
| where recon=1
| stats count as recon_count values(CommandLine) as commands min(_time) as first_seen max(_time) as last_seen by User, Computer
| where recon_count >= 3
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table first_seen, last_seen, User, Computer, recon_count, commands
```

### Tuning logic
**Why not filter by identity (e.g. exclude SYSTEM)?**  
Identity-based filtering assumes the identity is trustworthy. In a real
breach, the compromised identity is exactly what the attacker uses.
Filtering by identity removes the scenario you are trying to catch.

**Why chain detection instead of single command?**  
whoami and systeminfo are run legitimately by developers and admins constantly.
Alerting on every execution creates alert fatigue. A chain of 3+ recon
commands within 15 minutes from one user is behaviorally distinct from
normal admin activity.

### True Positive Example
- **User:** Target\shach  
- **Machine:** Target  
- **Commands seen:** systeminfo, whoami, whoami /priv  
- **recon_count:** 3  
- **Window:** 2026-06-27 12:17 to 12:32  

### False Positives identified
- A sysadmin running diagnostics manually could trigger this
- Automated monitoring scripts that check system state periodically
- Tune threshold upward (>=5) in high-activity environments

### Blind Spots / What this misses
- Recon spread across longer time windows (attacker being slow and deliberate)
- Recon using PowerShell equivalents: Get-LocalUser, Get-LocalGroupMember
- WMI-based enumeration: wmic useraccount list, wmic group list
- Recon via living-off-the-land binaries not in the match pattern
- Commands run under a different user context after lateral movement

### Recommended response
1. Check first_seen and last_seen — how long was the attacker active?
2. Identify what commands were run — did they escalate to net localgroup administrators?
3. Cross-reference with T1136.001 alert — did account creation follow the recon?
4. Check for outbound network connections (Sysmon EID 3) from the same host in the same window
5. If unauthorized — isolate the machine, preserve logs, escalate
