## Detection: LSASS Credential Access

**MITRE ATT&CK:** T1003 - OS Credential Dumping
**Severity:** Critical
**Author:** Shachin P R 
**Date:** 2026-07-05

---

### What it detects
Any process opening a handle to lsass.exe (Local Security Authority
Subsystem Service) with suspicious access rights. LSASS holds all
active user credentials in memory including plaintext passwords,
NTLM hashes, and Kerberos tickets. This detection fires when a
non-system process attempts to read LSASS memory — the core
behavior of credential dumping tools like Mimikatz, ProcDump,
and Meterpreter.

---

### Why LSASS is the crown jewel
LSASS keeps credentials in memory to handle transparent
authentication for network shares, printers, and domain resources.
A successful LSASS dump gives the attacker:
- Plaintext passwords (via WDigest cache)
- NTLM hashes (usable for Pass-the-Hash attacks)
- Kerberos tickets (usable for Pass-the-Ticket attacks)
- Service account credentials
- Domain admin credentials if logged in

One successful LSASS dump can compromise an entire domain.

---

### How the attack works
Attacker lands on machine
↓
Runs mimikatz.exe / procdump.exe / PowerShell
↓
OpenProcess(lsass.exe) with high access rights
↓           ← Sysmon EID 10 fires here
MiniDumpWriteDump() or direct memory read
↓
Credentials extracted from memory
↓
Pass-the-Hash / Pass-the-Ticket / lateral movement
---

### Sysmon Event ID used
**EID 10 — ProcessAccess**
Logs when one process opens a handle to another process.
Key fields:
- SourceImage — the process doing the accessing
- TargetImage — the process being accessed (lsass.exe)
- GrantedAccess — the access rights requested (most important field)

---

### GrantedAccess values explained
Windows access rights are bitmask values. Higher values = more
dangerous access. Key values for LSASS attacks:

| GrantedAccess | Meaning | Risk |
|---|---|---|
| 0x1000 | Query limited info | Low — normal system behavior |
| 0x2000 | Query info | Low — normal system behavior |
| 0x1400 | Read control + query | Medium — monitor |
| 0x1010 | VM read | High — memory reading capability |
| 0x1410 | Read memory | Critical — credential dump capable |
| 0x143a | Read + write memory | Critical — full dump capable |
| 0x1f3fff | Near full access | Critical — PowerShell/Mimikatz level |
| 0x1fffff | Full process access | Critical — complete control |

---

### SPL Query
```spl
index="main" EventCode=10 earliest=-24h
| where like(lower(TargetImage), "%lsass%")
| where NOT (GrantedAccess="0x1000" OR GrantedAccess="0x2000")
| where NOT (SourceImage="C:\\WINDOWS\\system32\\svchost.exe")
| where NOT (SourceImage="C:\\WINDOWS\\system32\\taskmgr.exe")
| where NOT (SourceImage="C:\\WINDOWS\\System32\\csrss.exe")
| where NOT (SourceImage="C:\\WINDOWS\\System32\\wininit.exe")
| where NOT (SourceImage="C:\\WINDOWS\\System32\\VBoxService.exe")
| where NOT (GrantedAccess="0x1400" OR GrantedAccess="0x1000000")
| eval risk=case(
    GrantedAccess="0x1fffff", "CRITICAL-FullAccess",
    GrantedAccess="0x1f3fff", "CRITICAL-PowerShellLSASSAccess",
    GrantedAccess="0x1410", "CRITICAL-MemoryRead",
    GrantedAccess="0x143a", "CRITICAL-ReadWrite",
    GrantedAccess="0x1010", "HIGH-VMRead",
    1=1, "HIGH-SuspiciousAccess"
)
| table _time, User, SourceImage, GrantedAccess, risk, Computer
| sort -_time
```

---

### Sysmon configuration required
This detection requires ProcessAccess monitoring enabled in
sysmon-config.xml. Default Sysmon configs do not include this.

Config used in this lab:
```xml
<RuleGroup name="" groupRelation="or">
  <ProcessAccess onmatch="include">
    <TargetImage condition="is">C:\Windows\system32\lsass.exe</TargetImage>
  </ProcessAccess>
</RuleGroup>
```

Applied via: `Sysmon64.exe -c C:\sysmon-config.xml`

---

### Baseline noise identified
| SourceImage | GrantedAccess | Verdict |
|---|---|---|
| svchost.exe | 0x1000, 0x2000 | Legitimate — Windows auth services |
| taskmgr.exe | 0x1000 | Legitimate — Task Manager display |
| csrss.exe | 0x1fffff | Legitimate — Windows boot process only |
| wininit.exe | 0x1fffff, 0x1000000 | Legitimate — Windows boot process only |
| VBoxService.exe | 0x1400 | Legitimate — VirtualBox guest additions |

**Critical note on boot storm:**
During BitLocker recovery boot, Windows system processes access
LSASS with full access rights (0x1fffff) during initialization.
This generates hundreds of CRITICAL-labeled events that are all
legitimate. Filter by excluding boot-time processes (csrss.exe,
wininit.exe) rather than excluding the access rights themselves —
otherwise real attacks during boot would be missed.

---

### True Positive Example
**PowerShell LSASS access simulation**
That is your attack event. Look at that GrantedAccess value:

0x1f3fff

That is essentially full access to LSASS. Breaking it down:

0x1f3fff = PROCESS_ALL_ACCESS (almost)
         = Read memory + Write memory + Create threads + Full control

This is exactly what Mimikatz requests. taskmgr.exe and svchost.exe only requested 0x1000 — read-only query. PowerShell opened LSASS with 0x1f3fff — that's an attacker-level access request.

This is your true positive. One event, powershell.exe → lsass.exe, GrantedAccess=0x1f3fff. In a real SOC this is an immediate P1 incident.
Now build your final detection
spl

index="main" EventCode=10
| where like(lower(TargetImage), "%lsass%")
| where NOT (GrantedAccess="0x1000" OR GrantedAccess="0x2000")
| where NOT (SourceImage="C:\\WINDOWS\\system32\\svchost.exe")
| where NOT (SourceImage="C:\\WINDOWS\\system32\\taskmgr.exe")
| eval risk=case(
    GrantedAccess="0x1fffff", "CRITICAL-FullAccess",
    GrantedAccess="0x1f3fff", "CRITICAL-PowerShellLSASSAccess",
    GrantedAccess="0x1410", "CRITICAL-MemoryRead",
    GrantedAccess="0x143a", "CRITICAL-ReadWrite",
    GrantedAccess="0x1010", "HIGH-VMRead",
    1=1, "HIGH-SuspiciousAccess"
)
| table _time, User, SourceImage, GrantedAccess, risk, Computer
| sort -_time

Run it — should return exactly your one PowerShell event labelled CRITICAL-PowerShellLSASSAccess.

Share the result then save the alert as DETECT - LSASS Credential Access (T1003) and request the full documentation.

2,166 events — that's the BitLocker recovery boot generating a massive amount of LSASS access. Windows during recovery mode touches LSASS constantly with high privilege access rights. That's why you see csrss.exe and wininit.exe with 0x1fffff — those are system boot processes.

Change time range to Last 7 days and add one more filter to exclude the boot storm:
spl

index="main" EventCode=10
| where like(lower(TargetImage), "%lsass%")
| where NOT (GrantedAccess="0x1000" OR GrantedAccess="0x2000")
| where NOT (SourceImage="C:\\WINDOWS\\system32\\svchost.exe")
| where NOT (SourceImage="C:\\WINDOWS\\system32\\taskmgr.exe")
| where NOT (SourceImage="C:\\WINDOWS\\System32\\csrss.exe")
| where NOT (SourceImage="C:\\WINDOWS\\System32\\wininit.exe")
| where NOT (SourceImage="C:\\WINDOWS\\System32\\VBoxService.exe")
| where NOT (GrantedAccess="0x1400" OR GrantedAccess="0x1000000")
| eval risk=case(
    GrantedAccess="0x1fffff", "CRITICAL-FullAccess",
    GrantedAccess="0x1f3fff", "CRITICAL-PowerShellLSASSAccess",
    GrantedAccess="0x1410", "CRITICAL-MemoryRead",
    GrantedAccess="0x143a", "CRITICAL-ReadWrite",
    GrantedAccess="0x1010", "HIGH-VMRead",
    1=1, "HIGH-SuspiciousAccess"
)
| table _time, User, SourceImage, GrantedAccess, risk, Computer
| sort -_time

Run on Last 7 days. Should surface your PowerShell event cleanly. Share result.

last 7 days it contains more last 15min its whows crtical things also

That's the boot storm from BitLocker recovery polluting the data. Change time range to Last 24 hours and run — that should skip the boot events from earlier and show only your PowerShell attack event cleanly.

Also add a time filter to start after you finished booting — around 13:15 today:
spl

index="main" EventCode=10 earliest="2026-07-05T13:15:00" latest=now
| where like(lower(TargetImage), "%lsass%")
| where NOT (GrantedAccess="0x1000" OR GrantedAccess="0x2000")
| where NOT (SourceImage="C:\\WINDOWS\\system32\\svchost.exe")
| where NOT (SourceImage="C:\\WINDOWS\\system32\\taskmgr.exe")
| where NOT (SourceImage="C:\\WINDOWS\\System32\\csrss.exe")
| where NOT (SourceImage="C:\\WINDOWS\\System32\\wininit.exe")
| where NOT (SourceImage="C:\\WINDOWS\\System32\\VBoxService.exe")
| where NOT (GrantedAccess="0x1400" OR GrantedAccess="0x1000000")
| eval risk=case(
    GrantedAccess="0x1fffff", "CRITICAL-FullAccess",
    GrantedAccess="0x1f3fff", "CRITICAL-PowerShellLSASSAccess",
    GrantedAccess="0x1410", "CRITICAL-MemoryRead",
    GrantedAccess="0x143a", "CRITICAL-ReadWrite",
    GrantedAccess="0x1010", "HIGH-VMRead",
    1=1, "HIGH-SuspiciousAccess"
)
| table _time, User, SourceImage, GrantedAccess, risk, Computer
| sort -_time

Share the result.

okay is this enough to write documentation

Yes. You have everything needed:

    True positive captured — powershell.exe → lsass.exe with GrantedAccess=0x1f3fff
    Baseline noise identified — taskmgr, svchost, csrss, wininit, VBoxService
    Boot storm documented — BitLocker recovery generates false CRITICAL events
    Blind spot discovered — PPL blocks ProcDump at kernel level, Sysmon misses it
    Detection tuned — exclusions written for all legitimate sources

That's actually a richer documentation story than a clean lab would give you. The BitLocker incident, the PPL blocking, the boot storm — all of that becomes real-world context in your doc that shows you understand the environment, not just the tool.

Request the full doc and I'll generate it now.

yeah generate now

Here you go:
markdown

## Detection: LSASS Credential Access

**MITRE ATT&CK:** T1003 - OS Credential Dumping
**Severity:** Critical
**Author:** Shachin P R (NOCTRIX Security)
**Date:** 2026-07-05

---

### What it detects
Any process opening a handle to lsass.exe (Local Security Authority
Subsystem Service) with suspicious access rights. LSASS holds all
active user credentials in memory including plaintext passwords,
NTLM hashes, and Kerberos tickets. This detection fires when a
non-system process attempts to read LSASS memory — the core
behavior of credential dumping tools like Mimikatz, ProcDump,
and Meterpreter.

---

### Why LSASS is the crown jewel
LSASS keeps credentials in memory to handle transparent
authentication for network shares, printers, and domain resources.
A successful LSASS dump gives the attacker:
- Plaintext passwords (via WDigest cache)
- NTLM hashes (usable for Pass-the-Hash attacks)
- Kerberos tickets (usable for Pass-the-Ticket attacks)
- Service account credentials
- Domain admin credentials if logged in

One successful LSASS dump can compromise an entire domain.

---

### How the attack works

Attacker lands on machine
↓
Runs mimikatz.exe / procdump.exe / PowerShell
↓
OpenProcess(lsass.exe) with high access rights
↓ ← Sysmon EID 10 fires here
MiniDumpWriteDump() or direct memory read
↓
Credentials extracted from memory
↓
Pass-the-Hash / Pass-the-Ticket / lateral movement


---

### Sysmon Event ID used
**EID 10 — ProcessAccess**
Logs when one process opens a handle to another process.
Key fields:
- SourceImage — the process doing the accessing
- TargetImage — the process being accessed (lsass.exe)
- GrantedAccess — the access rights requested (most important field)

---

### GrantedAccess values explained
Windows access rights are bitmask values. Higher values = more
dangerous access. Key values for LSASS attacks:

| GrantedAccess | Meaning | Risk |
|---|---|---|
| 0x1000 | Query limited info | Low — normal system behavior |
| 0x2000 | Query info | Low — normal system behavior |
| 0x1400 | Read control + query | Medium — monitor |
| 0x1010 | VM read | High — memory reading capability |
| 0x1410 | Read memory | Critical — credential dump capable |
| 0x143a | Read + write memory | Critical — full dump capable |
| 0x1f3fff | Near full access | Critical — PowerShell/Mimikatz level |
| 0x1fffff | Full process access | Critical — complete control |

---

### SPL Query
```spl
index="main" EventCode=10 earliest=-24h
| where like(lower(TargetImage), "%lsass%")
| where NOT (GrantedAccess="0x1000" OR GrantedAccess="0x2000")
| where NOT (SourceImage="C:\\WINDOWS\\system32\\svchost.exe")
| where NOT (SourceImage="C:\\WINDOWS\\system32\\taskmgr.exe")
| where NOT (SourceImage="C:\\WINDOWS\\System32\\csrss.exe")
| where NOT (SourceImage="C:\\WINDOWS\\System32\\wininit.exe")
| where NOT (SourceImage="C:\\WINDOWS\\System32\\VBoxService.exe")
| where NOT (GrantedAccess="0x1400" OR GrantedAccess="0x1000000")
| eval risk=case(
    GrantedAccess="0x1fffff", "CRITICAL-FullAccess",
    GrantedAccess="0x1f3fff", "CRITICAL-PowerShellLSASSAccess",
    GrantedAccess="0x1410", "CRITICAL-MemoryRead",
    GrantedAccess="0x143a", "CRITICAL-ReadWrite",
    GrantedAccess="0x1010", "HIGH-VMRead",
    1=1, "HIGH-SuspiciousAccess"
)
| table _time, User, SourceImage, GrantedAccess, risk, Computer
| sort -_time
```

---

### Sysmon configuration required
This detection requires ProcessAccess monitoring enabled in
sysmon-config.xml. Default Sysmon configs do not include this.

Config used in this lab:
```xml
<RuleGroup name="" groupRelation="or">
  <ProcessAccess onmatch="include">
    <TargetImage condition="is">C:\Windows\system32\lsass.exe</TargetImage>
  </ProcessAccess>
</RuleGroup>
```

Applied via: `Sysmon64.exe -c C:\sysmon-config.xml`

---

### Baseline noise identified
| SourceImage | GrantedAccess | Verdict |
|---|---|---|
| svchost.exe | 0x1000, 0x2000 | Legitimate — Windows auth services |
| taskmgr.exe | 0x1000 | Legitimate — Task Manager display |
| csrss.exe | 0x1fffff | Legitimate — Windows boot process only |
| wininit.exe | 0x1fffff, 0x1000000 | Legitimate — Windows boot process only |
| VBoxService.exe | 0x1400 | Legitimate — VirtualBox guest additions |

**Critical note on boot storm:**
During BitLocker recovery boot, Windows system processes access
LSASS with full access rights (0x1fffff) during initialization.
This generates hundreds of CRITICAL-labeled events that are all
legitimate. Filter by excluding boot-time processes (csrss.exe,
wininit.exe) rather than excluding the access rights themselves —
otherwise real attacks during boot would be missed.

---

### True Positive Example
**PowerShell LSASS access simulation**

Time: 2026-07-05 13:11:20
SourceImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
TargetImage: C:\WINDOWS\system32\lsass.exe
GrantedAccess: 0x1f3fff
Risk label: CRITICAL-PowerShellLSASSAccess
Computer: Target
User: (blank — see known limitation below
This was triggered via:
```powershell
$lsasspid = (Get-Process lsass).Id
$proc = [System.Diagnostics.Process]::GetProcessById($lsasspid)
```

`GetProcessById()` internally calls `OpenProcess()` with near-full
access rights — identical to what Mimikatz does before reading
credential structures from memory.

---

### Known limitation: PPL blocking
Windows Protected Process Light (PPL) prevents tools like ProcDump
from accessing LSASS at the kernel level. When PPL is active:
- `procdump64.exe -ma lsass.exe` returns Access Denied (0x00000005)
- The OpenProcess() call is blocked before Sysmon's driver hooks it
- **No EID 10 is generated — the attack attempt is invisible**

This means a sophisticated attacker who uses PPL bypass techniques
(Mimikatz driver, BYOVD attacks) can dump LSASS without triggering
this detection.

**Lab note:** Attempting to disable PPL via registry
(`RunAsPPL=0`) triggered BitLocker recovery on this VM because
TPM detected the security policy change as tampering. This
demonstrates how Windows security layers are interconnected —
disabling one control triggers another.

---

### False Positives identified
- Windows boot processes (csrss.exe, wininit.exe) access LSASS
  with full rights during system initialization — excluded by
  SourceImage filter
- VirtualBox guest service accesses LSASS for session monitoring
  — excluded by SourceImage filter
- Security products and EDR agents legitimately access LSASS
  for monitoring — add their paths to exclusion list
- Windows Defender accesses LSASS for credential guard — exclude
  MsMpEng.exe if it appears

---

### Blind Spots / What this misses
- **PPL bypass attacks:** Mimikatz `!+` driver loads a kernel
  driver to bypass PPL entirely — no EID 10 generated
- **BYOVD (Bring Your Own Vulnerable Driver):** Attackers load
  a legitimate but vulnerable driver to disable PPL at kernel
  level — completely bypasses this detection
- **Shadow copy credential theft:** Attackers copy LSASS from
  Volume Shadow Copies instead of live memory — no process
  access to lsass.exe involved
- **DCSync attack (T1003.006):** Replicates credentials from
  domain controller using legitimate AD replication protocol
  — no LSASS access on the endpoint at all
- **User field blank:** EID 10 does not reliably populate the
  User field for system-level access — attacker identity lost

---

### Recommended response
1. **Immediate:** Check risk label — CRITICAL requires instant action
2. Identify SourceImage — is it a known tool (mimikatz.exe,
   procdump.exe) or a renamed binary?
3. Check GrantedAccess value against table above — 0x1f3fff
   or higher means full credential access was attempted
4. Look for follow-on activity within 60 seconds:
   - New outbound connections (EID 3) — C2 callback with creds
   - New user accounts (T1136.001 alert) — persistence
   - Lateral movement attempts to other hosts
5. Check if a .dmp file was created on disk:
dir C:*.dmp /s
dir C:\Users*\AppData\Local\Temp*.dmp
6. **If confirmed:** Assume ALL credentials on this machine are
   compromised. Force password reset for every account that
   was logged into this machine. Isolate immediately.
7. Preserve memory dump of the machine before shutdown —
   volatile evidence contains attacker artifacts
8. Escalate to IR team with: timestamp, SourceImage,
   GrantedAccess value, and list of accounts logged into
   the machine

---
