## Detection: Process Injection via CreateRemoteThread

**MITRE ATT&CK:** T1055 - Process Injection
**Severity:** High
**Author:** Shachin P R 
**Date:** 2026-07-04

---

### What it detects
Remote thread creation from one process into another using the
Windows CreateRemoteThread API. This is the most common process
injection technique used by malware, RATs, and post-exploitation
frameworks like Cobalt Strike and Metasploit to hide malicious
code inside legitimate trusted processes.

---

### Why process injection is dangerous
Injecting into a trusted process like powershell.exe, explorer.exe,
or lsass.exe gives the attacker:
- Code execution under a trusted process identity
- Evasion of application whitelisting
- Access to the target process's memory and privileges
- In the case of lsass.exe — direct access to credentials

---

### Sysmon Event IDs used
| Event ID | Name | What it captures |
|---|---|---|
| EID 8 | CreateRemoteThread | Source injecting into target process |
| EID 10 | ProcessAccess | Process opening handle to another process |

This detection uses EID 8. EID 10 requires additional Sysmon
config (ProcessAccess monitoring) not enabled in this lab.

---

### SPL Query
```spl
index="main" EventCode=8
| eval suspicious=case(
    like(TargetImage, "%lsass%"), "CRITICAL-LSASSInjection",
    like(TargetImage, "%csrss%"), "HIGH-CSRSSInjection",
    like(SourceImage, "%unknown%") OR isnull(SourceImage), "HIGH-UnknownSourceInjection",
    like(SourceImage, "%powershell%") AND NOT like(TargetImage, "%powershell%"), "HIGH-PowerShellInjection",
    like(SourceImage, "%cmd.exe%"), "MEDIUM-CMDInjection",
    1=1, "LOW-ReviewRequired"
)
| table _time, User, suspicious, SourceImage, TargetImage, Computer
| sort _time
```

---

### Severity classification logic
| Label | Reason |
|---|---|
| CRITICAL-LSASSInjection | LSASS holds all credential material — injection means instant credential dump |
| HIGH-CSRSSInjection | csrss.exe is a protected system process — injection requires SYSTEM privileges |
| HIGH-UnknownSourceInjection | Source process exited before Sysmon captured it — deliberate evasion |
| HIGH-PowerShellInjection | PowerShell injecting into other processes — likely malicious script behavior |
| MEDIUM-CMDInjection | cmd.exe as source — suspicious but could be legitimate automation |
| LOW-ReviewRequired | Known process pairs — review manually |

---

### Known limitation: missing User field
EID 8 does not reliably populate the User field. When injection
occurs at system level or when the source process exits immediately,
Windows has no user token to associate with the thread creation event.

**Impact:** You know what happened, when, and where — but not who.

**Workaround — event correlation:**
```spl
index="main" EventCode=8
| where isnull(User) OR User=""
| eval injection_time=_time
| join Computer [
    search index="main" EventCode=1
    | table _time, User, Computer, CommandLine
]
| where abs(_time - injection_time) < 60
| table injection_time, _time, User, CommandLine, TargetImage, Computer
```
This correlates EID 8 events with EID 1 process creations on the
same machine within 60 seconds to recover user context.

---

### Baseline noise identified
| SourceImage | TargetImage | Verdict |
|---|---|---|
| dwm.exe | csrss.exe | Legitimate Windows graphics rendering |
| unknown process | powershell.exe | Suspicious — investigate |

The `dwm.exe → csrss.exe` pattern is known Windows behavior
(Desktop Window Manager → Client Server Runtime for UI rendering).
It is labeled HIGH but is expected in this environment.

---

### True Positive Examples
**Test 1 — Unknown source injecting into PowerShell**
Time: 2026-06-29 15:19:30
SourceImage: <unknown process>
TargetImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Label: HIGH-UnknownSourceInjection
Note: Source process exited before Sysmon capture — deliberate evasion

**Test 2 — mavinject.exe simulation**
Time: 2026-07-04 17:32:40
SourceImage: <unknown process>
TargetImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Label: HIGH-UnknownSourceInjection
Tool used: mavinject.exe (Microsoft-signed LOLBIN)
Note: mavinject.exe exits immediately after injection — vanishes from
process list before Sysmon captures SourceImage

---

### Living off the Land — mavinject.exe
`mavinject.exe` is a Microsoft-signed binary built into Windows,
originally designed for App-V application virtualization. Attackers
abuse it because:
- It is signed by Microsoft — trusted by AV and whitelisting tools
- It performs real DLL injection natively
- It exits immediately after injecting — evades process-based detection
- Command syntax: `mavinject.exe <PID> /INJECTRUNNING <DLL_PATH>`

This is called a Living Off the Land Binary (LOLBIN). The attacker
uses what Windows already provides — no malware download needed.

---

### False Positives identified
- dwm.exe → csrss.exe is legitimate Windows UI behavior
- Security tools and EDR agents create remote threads legitimately
  for monitoring purposes
- Game anti-cheat software commonly uses CreateRemoteThread
- Tune by adding known security tool paths to exclusion list

---

### Blind Spots / What this misses
- **APC injection (T1055.004):** Uses QueueUserAPC instead of
  CreateRemoteThread — no EID 8 generated
- **Process hollowing (T1055.012):** Replaces legitimate process
  memory without creating a remote thread — no EID 8 generated
- **Reflective DLL injection:** Loads DLL from memory without
  touching disk or creating remote threads in detectable ways
- **EID 10 not configured:** ProcessAccess monitoring disabled in
  this lab's Sysmon config — misses handle-based injection attempts
- **User attribution lost:** Source process exit before Sysmon
  capture removes attacker identity from the log

---

### Recommended response
1. Check the `suspicious` label — CRITICAL and HIGH need immediate action
2. If TargetImage is lsass.exe — treat as active credential theft, P1 incident
3. Correlate with EID 1 events on same machine within 60 seconds
   to recover user context
4. Check if a new outbound network connection (EID 3) followed
   the injection within 2 minutes — indicates C2 callback
5. Cross-reference with T1059.001 alert — was PowerShell running
   suspicious commands before or after the injection?
6. If confirmed malicious — isolate machine immediately,
   take memory dump before shutdown (volatile evidence)
7. Escalate to IR team with: timestamp, TargetImage, Computer,
   and correlated user from EID 1

---
