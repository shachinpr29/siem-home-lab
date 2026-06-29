## Detection: Suspicious PowerShell Execution

**MITRE ATT&CK:** T1059.001 - Command and Scripting Interpreter: PowerShell
**Severity:** High
**Author:** Shachin P R
**Date:** 2026-06-29

---

### What it detects
Suspicious PowerShell execution patterns commonly used by attackers
including encoded commands, execution policy bypass, hidden windows,
and web-based payload downloads. Excludes known legitimate PowerShell
noise from Splunk Universal Forwarder.

---

### Why PowerShell is abused
PowerShell is built into every Windows machine, trusted by default,
and can access the entire Windows API. Attackers use it to download
malware, enumerate systems, move laterally, and execute shellcode —
all without dropping a single file to disk. This is called
"living off the land" — using tools the OS already provides.

---

### SPL Query
```spl
index="main" EventCode=1
| where like(lower(Image), "%powershell%")
| where NOT like(Image, "%SplunkUniversalForwarder%")
| eval suspicious=case(
    like(CommandLine, "%-EncodedCommand%"), "EncodedCommand",
    like(CommandLine, "%-ExecutionPolicy Bypass%"), "ExecutionPolicyBypass",
    like(CommandLine, "%-WindowStyle Hidden%"), "HiddenWindow",
    like(CommandLine, "%-NonInteractive%") AND like(CommandLine, "%-NoProfile%"), "NonInteractiveNoProfile",
    like(CommandLine, "%IEX%") OR like(CommandLine, "%Invoke-Expression%"), "InvokeExpression",
    like(CommandLine, "%Net.WebClient%") OR like(CommandLine, "%DownloadString%"), "WebDownload",
    1=1, "clean"
)
| where suspicious!="clean"
| table _time, User, suspicious, CommandLine, ParentImage, Computer
| sort _time
```

---

### Detection logic explained
The `case()` function evaluates each CommandLine against known
suspicious flags in order. The first match wins and labels the event.
This approach gives the analyst immediate context without reading
the raw CommandLine.

| Label | What it means | Severity |
|---|---|---|
| EncodedCommand | Base64 hidden payload | Critical |
| ExecutionPolicyBypass | Overriding security policy | High |
| HiddenWindow | Invisible execution | High |
| NonInteractiveNoProfile | Scripted, not human | Medium |
| InvokeExpression | Executing downloaded code | Critical |
| WebDownload | Pulling payload from internet | Critical |

---

### Baseline noise identified
Before writing this detection, the following legitimate PowerShell
activity was found in the environment:

- **Splunk Universal Forwarder** runs `splunk-powershell.exe` as
  `NT AUTHORITY\SYSTEM` every ~2 minutes for Windows data collection
- Excluded via `NOT like(Image, "%SplunkUniversalForwarder%")`
- ParentImage for Splunk noise is blank — real attacks always have
  a ParentImage

---

### True Positive Examples
**Test 1 — ExecutionPolicy Bypass**
User: Target\shach

Time: 2026-06-29 15:18:10

CommandLine: powershell.exe -ExecutionPolicy Bypass -Command whoami

ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

**Test 2 — Hidden Window**
User: Target\shach

Time: 2026-06-29 15:18:34

CommandLine: powershell.exe -WindowStyle Hidden -NonInteractive -Command Get-LocalUser

ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

**Test 3 — Encoded Command**
User: Target\shach

Time: 2026-06-29 15:19:22

CommandLine: powershell.exe -EncodedCommand dwBoAG8AYQBtAGkA

Decoded: whoami
ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
---

### False Positives identified
- Splunk Universal Forwarder PowerShell — excluded by image path filter
- Legitimate admin scripts using -ExecutionPolicy Bypass for automation
  — tune by adding known admin machine hostnames to exclusion list
- Software installers that use -NonInteractive during silent install
  — check ParentImage for installer processes like msiexec.exe

---

### Critical ParentImage context
The ParentImage field tells you what launched PowerShell.
This changes the severity of the alert entirely:

| ParentImage | Meaning | Action |
|---|---|---|
| explorer.exe | Human ran it manually | Investigate |
| powershell.exe | Script spawned another shell | High priority |
| winword.exe / excel.exe | Malicious macro — phishing | P1 Incident |
| cmd.exe | Batch script or manual | Investigate |
| wscript.exe / cscript.exe | VBScript/JScript delivery | High priority |
| svchost.exe | Service-triggered execution | Critical |

---

### Blind Spots / What this misses
- **PowerShell v2 downgrade:** `powershell -Version 2` bypasses
  Script Block Logging entirely — no CommandLine detail logged
- **Renamed binary:** Attacker copies powershell.exe and renames it
  to svchost.exe or update.exe — image filter won't catch it
- **WMI/Scheduled Task delivery:** PowerShell invoked via WMI has
  a different ParentImage and may not match patterns
- **AMSI bypass:** Techniques that disable the Antimalware Scan
  Interface before script execution — runs before logging occurs
- **Constrained Language Mode bypass:** Via COM objects or
  PSRemoting — evades keyword detection entirely
- **No argument execution:** `powershell.exe` with no flags but
  script content piped via stdin — CommandLine shows nothing

---

### Recommended response
1. Check the `suspicious` label — EncodedCommand and WebDownload
   are automatic escalations
2. Decode any Base64 found in CommandLine:
   `[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("dwBoAG8AYQBtAGkA"))`
3. Check ParentImage — if winword.exe or excel.exe, treat as P1
4. Look for follow-on activity: did a network connection (EID 3)
   follow within 60 seconds from the same host?
5. Check if any new accounts were created (T1136.001 alert) from
   the same host in the same time window
6. If unauthorized — isolate the machine immediately, preserve
   memory dump if possible, escalate to IR team

---


