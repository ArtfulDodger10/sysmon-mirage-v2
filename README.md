# Sysmon Mirage v2 — Process Injection Detection Research

[![Language](https://img.shields.io/badge/Language-C%20%2F%20x64%20ASM-blue)](https://en.wikipedia.org/wiki/C_(programming_language))
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-T1055-red)](https://attack.mitre.org/techniques/T1055/)
[![Sysmon](https://img.shields.io/badge/Sysmon-v15.20-informational)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20x64-lightgrey)](https://www.microsoft.com/en-us/windows)

---

## What This Is

A controlled adversary emulation project that implements three T1055 process
injection techniques from scratch in C and x64 Assembly, captures the resulting
Sysmon telemetry, and builds detection logic based on what actually happened —
not what documentation says should happen.

The research question: as injection techniques evolve from noisy Win32 API abuse
toward stealthy syscall-based approaches, what telemetry survives, what
disappears, and where does the detection story break down?

**Author:** Nader Ayman
**Environment:** Windows 10 x64, Sysmon v15.20, schema 4.91
**Methodology:** Same payload, same target process, different delivery mechanism
per technique — isolating the telemetry delta to the injection method alone.

---
## Why I Built This
I wanted to understand process injection at a level deeper than reading
about it. Not just "here is what CreateRemoteThread does" — but what does
the kernel actually see, what does Sysmon actually capture, and where does
detection break down as techniques get more sophisticated. also I remember 
the first time when I faced a reversing CTF challenge that contained a shellcode,
that shellcode that caused me problems when I first heard about it in Practical 
Malware Analysis, and here it came to my head to dive and learn some about Malware 
Development, shellcodes, as well as my blue teaming studying.



## ATT&CK Technique Coverage

| Technique | ATT&CK ID | EID 8 | EID 10 | Sigma Rule | Confidence |
| :--- | :--- | :---: | :---: | :--- | :---: |
| Classic Win32 API Injection | T1055.001 | YES | YES | `win_classic_win32_injection.yml` | High |
| Direct Syscalls | T1055 | PARTIAL | YES | `win_direct_syscall_injection.yml` | Medium |
| Indirect Syscalls | T1055 | YES* | YES | `win_indirect_syscall_injection.yml` | Medium |

*Unexpected finding — documented in findings.md

---

## Repository Structure

```
sysmon-mirage-v2/
├── README.md
├── config_mirage_v2.xml
├── injectors/
│   ├── shellcode_artful.asm          — x64 MessageBox payload (NASM)
│   ├── classic_injection/
│   │   ├── classic_injection.c       — Win32 API injection via CreateRemoteThread
│   │   ├── handBag.h                 — Native API type definitions
│   │   └── classic_injection.exe     — Compiled binary
│   ├── direct_injection/
│   │   ├── direct_syscall_injection.c — NtCreateThreadEx via direct syscall
│   │   ├── syscalls.asm              — Direct syscall stubs (syscall instruction)
│   │   ├── handBag.h
│   │   └── directSysCall.exe         — Compiled binary
│   └── indirect_injection/
│       ├── indirect_syscall_injection.c — NtCreateThreadEx via indirect syscall
│       ├── syscalls.asm              — Indirect syscall stubs (jmp to ntdll)
│       ├── handBag.h
│       └── indirectSysCall.exe       — Compiled binary
├── Sigma Rules/
│   ├── win_classic_win32_injection.yml
│   ├── win_direct_syscall_injection.yml
│   └── win_indirect_syscall_injection.yml
├── evasion_testing/
│   └── stack_spoofing_analysis.md
├── Docs/
│   ├── findings.md
│   ├── Telemetry_Expectations_Matrix.md
│   ├── False_Positive_Tuning.md
│   ├── detection_gaps.md
│   └── Windows_Internals_Crash_Course.md
└── screenshots/
    ├── classic/
    ├── direct/
    └── indirect/
```

---

## How to Reproduce

### Requirements
- Windows 10 x64 VM (isolated, no production data)
- Sysmon v15.20 from Sysinternals
- MinGW-w64 (gcc + nasm)
- Windows Defender real-time protection disabled during emulation runs

### Step 1 — Install Sysmon
```
sysmon64.exe -accepteula -i config_mirage_v2.xml
```

Verify:
```
sysmon64.exe -c
```

### Step 2 — Compile Injectors

Classic injection:
```bash
gcc injectors/classic_injection.c -o classic_injection.exe -lkernel32
```

Direct syscalls:
```bash
nasm -f win64 injectors/syscalls.asm -o syscalls.o
gcc injectors/direct_syscall_injection.c syscalls.o -o directSysCall.exe -lntdll -lkernel32 -lwtsapi32 -lpsapi
```

Indirect syscalls:
```bash
nasm -f win64 injectors/syscalls_indirect.asm -o syscalls.o
gcc injectors/indirect_syscall_injection.c syscalls.o -o indirectSysCall.exe -lntdll -lkernel32 -lwtsapi32 -lpsapi
```

### Step 3 — Run Emulation

Open a fresh notepad.exe, then run each injector:
```powershell
Start-Process notepad.exe
.\classic_injection.exe
```

### Step 4 — Capture Telemetry

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
Where-Object {
    ($_.Id -eq 1 -or $_.Id -eq 8 -or $_.Id -eq 10) -and
    $_.Message -like "*injection*"
} |
Select-Object Id, TimeCreated, Message |
Format-List
```

---

## Key Findings

### Finding 1 — EID 10 is the Universal Anchor
Every technique generated EID 10 regardless of how the syscall was invoked.
Detection strategies built solely around EID 8 miss direct and indirect
syscall variants entirely. EID 10 CallTrace analysis is the reliable anchor.

### Finding 2 — Indirect Syscalls Generated EID 8 (Contradicts Documentation)
Published resources state indirect syscalls do not generate EID 8 because
they use NtCreateThreadEx rather than Win32 CreateRemoteThread. Testing on
Windows 10 x64 with Sysmon v15.20 produced EID 8 consistently for indirect
syscalls. Sysmon's kernel callback fires regardless of invocation method.

### Finding 3 — UNKNOWN Never Appeared in CallTrace on Windows 10
The commonly documented indicator for direct syscalls — UNKNOWN entries in
CallTrace — did not appear during testing. The real signature is injector
memory offsets appearing at the top of the CallTrace chain, indicating the
syscall was executed from attacker-controlled memory.

### Finding 4 — Direct Syscalls Produce a Distinctive Two-Event Signature
The WTSEnumerateProcessesA PID resolution call generates a first EID 10
with GrantedAccess 0x1000 and clean CallTrace. The injection itself generates
a second EID 10 with GrantedAccess 0x103A and broken CallTrace from the same
SourceProcessId. Correlating both events produces higher-confidence detection.

### Finding 5 — StartModule "-" is a Clean Classic Injection Indicator
EID 8 StartModule logs as "-" when a remote thread starts from shellcode in
unregistered memory. Legitimate software creating remote threads almost always
starts from a named, signed module. This field is underutilized in detection.

---

## Observed CallTrace Patterns

### Classic WinAPI Injection
```
C:\WINDOWS\SYSTEM32\ntdll.dll+9da64          ← legitimate origin
C:\WINDOWS\SYSTEM32\WINSTA.dll+30f8e
C:\WINDOWS\SYSTEM32\WTSAPI32.dll+7004
C:\Users\...\classic_injection.exe+15aa      ← injector visible deep in chain
C:\WINDOWS\System32\KERNEL32.DLL+17374
C:\WINDOWS\SYSTEM32\ntdll.dll+4cc91
GrantedAccess: 0x142A
```

### Direct Syscalls — Injection Event
```
C:\Users\...\directSysCall.exe+1b0b          ← injector at TOP = broken stack
C:\Users\...\directSysCall.exe+1858
C:\Users\...\directSysCall.exe+1ab8
C:\Users\...\directSysCall.exe+12fe
C:\Users\...\directSysCall.exe+1416
C:\WINDOWS\System32\KERNEL32.DLL+17374
C:\WINDOWS\SYSTEM32\ntdll.dll+4cc91
GrantedAccess: 0x103A
```

### Indirect Syscalls
```
C:\WINDOWS\SYSTEM32\ntdll.dll+9da64          ← ntdll at top = looks legitimate
C:\Users\...\indirectSysCall.exe+1945        ← but injector visible mid-chain
C:\Users\...\indirectSysCall.exe+1b97
C:\Users\...\indirectSysCall.exe+12fe
C:\Users\...\indirectSysCall.exe+1416
C:\WINDOWS\System32\KERNEL32.DLL+17374
C:\WINDOWS\SYSTEM32\ntdll.dll+4cc91
GrantedAccess: 0x103A
```

---

## Detection Logic

### Classic Win32 API Injection

Primary indicator — EID 8 with StartModule "-":
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
Where-Object {
    $_.Id -eq 8 -and
    $_.Message -like "*StartModule: -*" -and
    $_.Message -notlike "*wmpnetwk*"
}
```

Secondary indicator — EID 10 with high GrantedAccess:
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
Where-Object {
    $_.Id -eq 10 -and
    ($_.Message -like "*0x043A*" -or $_.Message -like "*0x1F1FFF*")
}
```

---

### Direct Syscalls

Primary indicator — injector path at top of CallTrace:
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
Where-Object {
    $_.Id -eq 10 -and
    $_.Message -like "*GrantedAccess: 0x103A*" -and
    $_.Message -notlike "*ntdll.dll+*`nC:\WINDOWS*"
}
```

---

### Indirect Syscalls

Primary indicator — ntdll at top with injector mid-chain:
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
Where-Object {
    $_.Id -eq 10 -and
    $_.Message -like "*ntdll.dll*" -and
    $_.Message -like "*\Users\*" -and
    $_.Message -like "*0x103A*"
}
```

---

## Detection Gaps

Sysmon has real blind spots that no configuration change can fix:

- **Memory allocation phase** — VirtualAllocEx and NtAllocateVirtualMemory
  generate no Sysmon events. The payload is written before any telemetry fires.
- **Stack spoofing** — Overwriting the call stack before telemetry capture
  defeats CallTrace-based detection entirely. 
- **BYOVD** — Kernel-mode attackers can unregister Sysmon's callbacks.
  Sysmon continues running but captures nothing.
- **Module stomping** — Code executing within legitimate DLL memory produces
  a clean-looking CallTrace from Sysmon's perspective.

See [Docs/detection_gaps.md](docs/detection_gaps.md) for full analysis.

---

## Sigma Rules

All three rules use field values derived from real observed telemetry.
GrantedAccess masks, CallTrace patterns, and StartModule values were
captured from actual emulation runs, not sourced from documentation.

| Rule | Key Detection Field | Real Value Observed |
| :--- | :--- | :--- |
| Classic | EID 8 StartModule | `-` |
| Classic | EID 10 GrantedAccess | `0x142A` |
| Direct | EID 10 CallTrace origin | Injector path at top |
| Direct | EID 10 GrantedAccess | `0x103A` |
| Indirect | EID 10 CallTrace pattern | ntdll top, injector mid-chain |
| Indirect | EID 8 presence | Unexpected — appeared in testing |

---
## Lessons Learned
The most frustrating moment in this project was building detection logic
around UNKNOWN entries in the CallTrace field for direct syscalls. This
pattern appears in nearly every blog post and detection engineering resource
covering direct syscall detection. It never appeared once in my testing on
Windows 10 with Sysmon v15.20. Hours of troubleshooting a Sysmon
configuration that was actually working correctly, looking for an indicator
that simply does not appear on this OS version.
The real signature — injector memory offsets at the top of the CallTrace —
only became clear after reading the raw events carefully and comparing them
against classic injection output side by side. That comparison, not any
documentation, was the breakthrough.
The indirect syscall EID 8 finding came the same way. I expected it not to
appear based on everything I had read. It appeared consistently. I spent
time trying to figure out what I had done wrong before accepting that the
documentation was describing behavior on older systems or older Sysmon
versions, not what I was seeing in front of me.
The Sysmon configuration debugging also taught something practical: AND
logic between SourceImage and CallTrace filters in schema 4.91 silently
drops events that match only one condition. This is not documented clearly
anywhere and cost significant time to isolate. The fix — separating them
into independent selections with OR condition logic — is now reflected in
the Sigma rules.
## Documentation

| Document | Description |
| :--- | :--- |
| [findings.md](docs/findings.md) | Five original research findings with detection implications |
| [Telemetry_Expectations_Matrix.md](docs/Telemetry_Expectations_Matrix.md) | Observed event matrix with real CallTrace values |
| [False_Positive_Tuning.md](docs/False_Positive_Tuning.md) | Real FP scenarios encountered during testing |
| [detection_gaps.md](docs/detection_gaps.md) | What Sysmon cannot see and why |
| [Windows_Internals_Crash_Course.md](docs/Windows_Internals_Crash_Course.md) | Background reading on user mode, kernel mode, and syscalls |

---

## Honest Scope Statement

This project provides reliable detection for injection techniques executed
from unsigned binaries in user-writable paths against common target processes
on systems where Sysmon is running and uncorrupted without stack spoofing.

That covers a meaningful portion of real-world attacks — commodity malware,
red team tooling, and less sophisticated threat actors. It does not cover
nation-state adversaries implementing stack spoofing, BYOVD, or kernel-level
evasion. The detection_gaps document covers exactly where coverage ends and why.
