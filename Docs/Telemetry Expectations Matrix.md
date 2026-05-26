# Telemetry Expectations Matrix

This matrix documents **observed** Sysmon telemetry from controlled adversary emulation
of three T1055 process injection techniques. All values are derived from real test runs
on Windows 10 x64 with Sysmon v15.20, not theoretical expectations.

---

## Observed Results

| Technique | ATT&CK ID | EID 1 | EID 7 | EID 8 | EID 10 | CallTrace Pattern | Visibility |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- | :---: |
| Classic WinAPI Injection | T1055.001 | YES | YES | YES | YES | Clean — ntdll.dll at top | HIGH |
| Direct Syscalls | T1055 | YES | YES | PARTIAL | YES | Injector offsets at top | MEDIUM |
| Indirect Syscalls | T1055 | YES | YES | YES* | YES | ntdll.dll at top, injector mid-chain | MEDIUM |


*Unexpected finding — see notes below.

---

## Real CallTrace Values Observed

### Classic WinAPI Injection
```
C:\WINDOWS\SYSTEM32\ntdll.dll+9da64
C:\WINDOWS\SYSTEM32\WINSTA.dll+30f8e
C:\WINDOWS\SYSTEM32\WTSAPI32.dll+7004
C:\Users\...\classic_injection.exe+15aa
C:\WINDOWS\System32\KERNEL32.DLL+17374
C:\WINDOWS\SYSTEM32\ntdll.dll+4cc91
```
**GrantedAccess observed:** `0x043A`
**Key indicator:** EID 8 StartModule field logs as `-` — thread starts from
unregistered memory (shellcode), no mapped module name.

---

### Direct Syscalls
Two EID 10 events generated per injection run:

**Event 1 — Process enumeration phase:**
```
C:\WINDOWS\SYSTEM32\ntdll.dll+9da64
C:\WINDOWS\SYSTEM32\WINSTA.dll+30f8e
C:\WINDOWS\SYSTEM32\WTSAPI32.dll+7004
C:\Users\...\directSysCall.exe+15aa
C:\WINDOWS\System32\KERNEL32.DLL+17374
C:\WINDOWS\SYSTEM32\ntdll.dll+4cc91
```
**GrantedAccess:** `0x1000`
**Note:** WTSEnumerateProcessesA reconnaissance call — looks legitimate.

**Event 2 — Actual injection:**
```
C:\Users\...\directSysCall.exe+1b0b
C:\Users\...\directSysCall.exe+1858
C:\Users\...\directSysCall.exe+1ab8
C:\Users\...\directSysCall.exe+12fe
C:\Users\...\directSysCall.exe+1416
C:\WINDOWS\System32\KERNEL32.DLL+17374
C:\WINDOWS\SYSTEM32\ntdll.dll+4cc91
```
**GrantedAccess:** `0x103A`
**Key indicator:** CallTrace starts with injector memory offsets — no ntdll.dll
at the top. Syscall executed directly from attacker-controlled memory,
breaking call stack integrity.

---

### Indirect Syscalls
```
C:\WINDOWS\SYSTEM32\ntdll.dll+9da64
C:\Users\...\indirectSysCall.exe+1945
C:\Users\...\indirectSysCall.exe+1b97
C:\Users\...\indirectSysCall.exe+12fe
C:\Users\...\indirectSysCall.exe+1416
C:\WINDOWS\System32\KERNEL32.DLL+17374
C:\WINDOWS\SYSTEM32\ntdll.dll+4cc91
```
**GrantedAccess:** `0x103A`
**Key indicator:** ntdll.dll appears at top mimicking legitimate behavior,
but injector memory offsets are visible mid-chain.

---

## Key Findings

### Finding 1 — CallTrace Degradation Across Techniques

Each technique produces a progressively harder-to-detect CallTrace pattern:

- **Classic:** Injector offsets only appear deep in chain, easy to correlate with EID 8
- **Direct:** Injector offsets appear at the TOP — broken call stack integrity, medium detection confidence
- **Indirect:** ntdll.dll at top looks legitimate, but injector still visible mid-chain

### Finding 2 — Unexpected EID 8 for Indirect Syscalls

Common documentation states indirect syscalls do not generate EID 8
(CreateRemoteThread) because they use NtCreateThreadEx via indirect syscall
rather than the Win32 CreateRemoteThread API. However, controlled testing on
Windows 10 x64 with Sysmon v15.20 produced EID 8 for indirect syscalls.

This suggests either Sysmon's kernel callback captures NtCreateThreadEx
regardless of how it is invoked, or the indirect syscall implementation
falls back to a detectable code path on this Windows version. This warrants
further investigation across different OS versions and Sysmon versions.

### Finding 3 — EID 10 as Universal Anchor

All three techniques generated EID 10 regardless of execution method.
Even when EID 8 was absent or partial, EID 10 fired consistently.
This validates EID 10 as the most reliable detection anchor for T1055.

### Finding 4 — Direct Syscalls Generate Two EID 10 Events

The WTSEnumerateProcessesA call used for PID resolution generates a
separate EID 10 with GrantedAccess 0x1000 and a clean-looking CallTrace.
This creates a two-event signature unique to this implementation that
can be used for higher-confidence detection.

---

## Detection Confidence by Technique

| Technique | Sigma Rule Confidence | Notes |
| :--- | :--- | :--- |
| Classic WinAPI | High | EID 8 + EID 10 together = strong signal |
| Direct Syscalls | Medium | Broken CallTrace detectable but requires path filtering |
| Indirect Syscalls | Medium | Higher than expected due to EID 8 finding |

---

## Event ID Reference

| Event ID | Purpose | Relevance to T1055 |
| :--- | :--- | :--- |
| 1 | Process Creation | Identifies injector binary and parent process |
| 7 | Image Load | DLL loads into target — key for indirect syscall correlation |
| 8 | CreateRemoteThread | Primary indicator for classic injection |
| 10 | ProcessAccess | Universal anchor — fires for all three techniques |

---

## Test Environment

- **OS:** Windows 10 x64
- **Sysmon:** v15.20, schema 4.91
- **Config:** config_mirage_v2.xml
- **Target process:** notepad.exe
- **EDR:** None active during testing
- **Defender:** Real-time protection disabled during emulation runs