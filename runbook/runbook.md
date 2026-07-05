# SOC Triage Runbook — NOCTRIX Security Home Lab

**Author:** Shachin P R (NOCTRIX Security)  
**Last Updated:** 2026-07-05  
**Environment:** Windows 11 Target + Splunk + Sysmon  

---

## How to use this runbook
Each section maps to one Splunk alert. When an alert fires:
1. Open the alert in Splunk Triggered Alerts
2. Find the matching section below
3. Follow steps in order
4. Document your findings at each step
5. Make escalation decision based on criteria provided

---

## Alert 1 — Local Account Creation (T1136.001)
**Severity:** High  
**Alert name:** DETECT - Local Account Creation via net.exe  
**Fires when:** net.exe or net1.exe runs with user + /add arguments  

### Step 1 — Identify who ran the command
```spl
index="main" EventCode=1
| where like(CommandLine, "%net%user%add%")
| where NOT like(CommandLine, "%localgroup%")
| table _time, User, CommandLine, Computer
```
- Who is the `User` field? Is it a known admin account?
- Is this a scheduled maintenance window?

### Step 2 — Check the account name created
Look at the CommandLine field:
- Does the account name look like a service account? (svc_, app_, etc.)
- Does it look like a human backdoor? (support, helpdesk, admin2)
- Is it a random string? (immediate escalation)

### Step 3 — Check for preceding recon
Did recon activity happen on this machine before account creation?
```spl
index="main" EventCode=1 Computer="<machine_name>" earliest=-30m
| where like(CommandLine, "%whoami%") OR like(CommandLine, "%net user%")
| table _time, User, CommandLine
```
If recon preceded account creation — **escalate immediately.**

### Step 4 — Escalation decision
| Condition | Action |
|---|---|
| Known admin, scheduled maintenance | Close as FP, document |
| Unknown user ran command | Escalate to Tier 2 |
| Random account name | P1 incident — isolate machine |
| Recon preceded creation | P1 incident — isolate machine |

### Step 5 — Containment if malicious
1. Disable the created account immediately:
   `net user <accountname> /active:no`
2. Isolate the machine from network
3. Preserve logs before any changes
4. Escalate to IR team

---

## Alert 2 — Recon Command Chain (T1033/T1069)
**Severity:** Medium  
**Alert name:** DETECT - Recon Command Chain  
**Fires when:** 3+ recon commands run from same user within 15 minutes  

### Step 1 — Review the command chain
```spl
index="main" EventCode=1 earliest=-30m
| eval recon=if(match(CommandLine,"whoami|net user|net localgroup|systeminfo|ipconfig|hostname"),1,0)
| where recon=1
| table _time, User, CommandLine, Computer
| sort _time
```
- What commands were run?
- In what order? (whoami first = attacker orienting themselves)
- How fast? (all within 60 seconds = scripted, not human)

### Step 2 — Identify the context
- Is this a developer machine? Devs run whoami and ipconfig regularly
- Is this a server? Any interactive recon on a server is suspicious
- Is there a logged helpdesk ticket for work on this machine?

### Step 3 — Check for follow-on activity
Did anything happen after the recon?
```spl
index="main" EventCode=1 Computer="<machine_name>" earliest=-1h
| table _time, User, CommandLine
| sort _time
```
Look for account creation, PowerShell execution, or network connections
following the recon window.

### Step 4 — Escalation decision
| Condition | Action |
|---|---|
| Developer machine, business hours | Verify with user, likely FP |
| Server machine, any recon | Escalate to Tier 2 |
| Recon followed by other alerts | P1 incident |
| Commands ran in under 60 seconds | Escalate — likely scripted |

---

## Alert 3 — Suspicious PowerShell (T1059.001)
**Severity:** High  
**Alert name:** DETECT - Suspicious PowerShell Execution  
**Fires when:** PowerShell runs with encoded commands, bypass flags,
or hidden window  

### Step 1 — Check the suspicious label
The alert includes a `suspicious` field:
- `EncodedCommand` — decode it immediately (Step 2)
- `ExecutionPolicyBypass` — check what command followed
- `HiddenWindow` — highest priority, attacker hiding execution
- `WebDownload` — P1, something was downloaded

### Step 2 — Decode encoded commands
If label is EncodedCommand, decode the Base64:
```powershell
[System.Text.Encoding]::Unicode.GetString(
  [System.Convert]::FromBase64String("<paste_base64_here>")
)
```
What does the decoded command do?

### Step 3 — Check ParentImage
This is the most important field:
| ParentImage | Meaning | Priority |
|---|---|---|
| explorer.exe | Human ran it | Medium |
| powershell.exe | Script spawned shell | High |
| winword.exe / excel.exe | Malicious macro | P1 NOW |
| wscript.exe | VBScript delivery | High |
| svchost.exe | Service triggered | Critical |

### Step 4 — Check for network connections
Did PowerShell make any outbound connections?
```spl
index="main" EventCode=3 Computer="<machine_name>" earliest=-5m
| table _time, User, Image, DestinationIp, DestinationPort
```
Any connection to external IP after PowerShell = C2 callback.

### Step 5 — Escalation decision
| Condition | Action |
|---|---|
| EncodedCommand + external connection | P1 — isolate immediately |
| ParentImage is Office application | P1 — malicious macro |
| ExecutionPolicyBypass, known admin | Verify with admin |
| HiddenWindow, any context | Escalate to Tier 2 |

---

## Alert 4 — Process Injection (T1055)
**Severity:** High  
**Alert name:** DETECT - Process Injection via CreateRemoteThread  
**Fires when:** A process creates a remote thread in another process  

### Step 1 — Identify source and target
```spl
index="main" EventCode=8
| table _time, User, SourceImage, TargetImage, Computer
| sort -_time
| head 10
```
- What is injecting into what?
- Is SourceImage a known tool or unknown process?

### Step 2 — Check for unknown source
If SourceImage = `<unknown process>`:
- The injector exited immediately after firing
- This is deliberate evasion — treat as high confidence malicious
- Correlate by time to find what ran 60 seconds before:
```spl
index="main" EventCode=1 Computer="<machine_name>"
| where _time > (relative_time(now(), "-2m"))
| table _time, User, CommandLine
```

### Step 3 — Check what the target process did after injection
Did the target process make unexpected network connections?
```spl
index="main" EventCode=3 Computer="<machine_name>"
| where Image="<TargetImage>"
| table _time, Image, DestinationIp, DestinationPort
```

### Step 4 — Escalation decision
| Condition | Action |
|---|---|
| dwm.exe → csrss.exe | Known FP — close |
| Unknown source → any process | Escalate to Tier 2 |
| Any source → lsass.exe | P1 — credential theft likely |
| Target process makes C2 connection | P1 — active compromise |

---

## Alert 5 — LSASS Credential Access (T1003)
**Severity:** Critical  
**Alert name:** DETECT - LSASS Credential Access  
**Fires when:** Non-system process opens handle to lsass.exe with
suspicious access rights  

### Step 1 — This is always high priority
Any non-system process accessing LSASS with elevated rights is
suspicious by definition. Do not dismiss without investigation.

### Step 2 — Check the GrantedAccess value
```spl
index="main" EventCode=10
| where like(lower(TargetImage), "%lsass%")
| table _time, User, SourceImage, GrantedAccess, Computer
| sort -_time
```
- 0x1f3fff or higher = assume credential dump attempted
- 0x1410 or 0x143a = memory read access = credential dump capable

### Step 3 — Check for dump file on disk
Was a .dmp file created?
```spl
index="main" EventCode=11
| where like(TargetFilename, "%.dmp%")
| table _time, User, Image, TargetFilename, Computer
```
If a .dmp file was created — credentials are confirmed stolen.

### Step 4 — Check for immediate follow-on
Within 5 minutes of the LSASS access:
- New outbound connections (EID 3) — credentials being exfiltrated
- New accounts created (T1136.001 alert) — persistence established
- Lateral movement to other machines

### Step 5 — Identify all accounts on the machine
These credentials must be considered compromised:
```powershell
# Run on affected machine
query user
net user
```
Every account that was logged into this machine needs
a forced password reset.

### Step 6 — Escalation decision
| Condition | Action |
|---|---|
| Any CRITICAL label | P1 — escalate immediately |
| SourceImage is known security tool | Verify with security team |
| Dump file found on disk | P1 — credentials confirmed stolen |
| Follow-on C2 connection | P1 — active exfiltration |

### Step 7 — Containment
1. Isolate machine immediately — pull network cable
2. Do NOT reboot — volatile memory contains attacker artifacts
3. Take memory dump of entire machine for forensics
4. Force password reset for ALL accounts on this machine
5. Check other machines for lateral movement using stolen creds
6. Escalate to IR team with full timeline

---

## Escalation contacts template
Tier 1 → Tier 2 escalation trigger: any P1 condition above
Tier 2 → IR team escalation trigger: confirmed compromise
Incident details to include:

Alert name and timestamp
Affected machine (Computer field)
User account involved
Specific indicator (CommandLine / GrantedAccess / TargetImage)
Any follow-on activity observed
Actions already taken


---

## Cross-alert correlation
Some attacks trigger multiple alerts. Common chains:

**Chain 1 — Full attack lifecycle:**
Alert 2 (Recon) → Alert 3 (PowerShell) → Alert 4 (Injection)
→ Alert 5 (LSASS) → Alert 1 (Account Creation)
If you see this chain from the same machine within 2 hours — 
active breach in progress. P1 immediately.

**Chain 2 — Quick persistence:**
Alert 3 (PowerShell) → Alert 1 (Account Creation)
Attacker used PowerShell to create a backdoor account.

**Chain 3 — Credential theft:**
Alert 2 (Recon) → Alert 5 (LSASS)
Attacker enumerated then dumped credentials.
