# Research Findings — Sysmon Mirage v2

Author Nader Ayman  
Date May 2026  
Environment Windows 10 x64, Sysmon v15.20, schema 4.91  
Target process notepad.exe  
Methodology Controlled adversary emulation — same payload, same target,
different delivery mechanism per technique  

---

## Overview

This document summarizes the detection engineering findings from emulating
three T1055 process injection techniques and analyzing the resulting Sysmon
telemetry. The research question was straightforward as injection techniques
evolve from noisy Win32 API abuse toward stealthy syscall-based approaches,
what telemetry survives and what disappears

The short answer is that EID 10 (ProcessAccess) survives everything. The
CallTrace field within it tells the full story.

---

## Three-Way Technique Comparison

  Classic WinAPI  Direct Syscalls  Indirect Syscalls 
 ---  ---  ---  --- 
 EID 1 (Process Create)  YES  YES  YES 
 EID 7 (Image Load)  YES  YES  YES 
 EID 8 (CreateRemoteThread)  YES  PARTIAL  YES 
 EID 10 (ProcessAccess)  YES  YES  YES 
 CallTrace starts with ntdll.dll  YES  NO  YES 
 Injector visible in CallTrace  NO  YES (top)  YES (middle) 
 Detection confidence  HIGH  MEDIUM  MEDIUM 
 ATT&CK ID  T1055.001  T1055  T1055 

Unexpected — see Finding 2 below.

---

## Finding 1 — EID 10 is the Universal Anchor

Every technique generated EID 10 regardless of how the syscall was invoked.
Classic injection, direct syscalls, and indirect syscalls all require the
injector to acquire privileged access to the target process memory — and that
access request always produces a ProcessAccess event.

This makes EID 10 the single most reliable detection anchor for T1055.
Detection strategies that rely solely on EID 8 (CreateRemoteThread) will
miss direct and indirect syscall variants entirely.

Detection implication Build your primary detection logic around EID 10
CallTrace analysis. Use EID 8 as a corroborating signal, not the primary one.

---

## Finding 2 — Indirect Syscalls Generated EID 8 (Unexpected)

Published documentation and most detection engineering resources state that
indirect syscalls do not generate EID 8 because they use NtCreateThreadEx
rather than the Win32 CreateRemoteThread API. This research found the opposite.

Indirect syscall testing on Windows 10 x64 with Sysmon v15.20 produced
EID 8 consistently. The most likely explanation is that Sysmon's kernel
callback (PsSetCreateThreadNotifyRoutine) fires regardless of whether the
thread was created via Win32 API or directindirect syscall — the kernel
operation is the same either way.

Detection implication Do not rely on EID 8 absence as an indicator
of advanced injection techniques. On modern Windows with current Sysmon
versions, EID 8 may appear for all three techniques.

Research implication This finding should be validated across different
Windows versions and Sysmon versions to determine if it is version-specific
behavior or a documentation gap across the board.

---

## Finding 3 — CallTrace Degrades Predictably Across Techniques

The CallTrace field in EID 10 tells a clear story about how each technique
works internally

Classic injection — CallTrace begins with ntdll.dll and progresses
through legitimate Windows modules. The injector appears deep in the chain
or not at all. Clean and expected.

Direct syscalls — CallTrace begins with the injector's own memory
offsets. No ntdll.dll at the top. The syscall instruction was executed
directly from attacker-controlled memory, breaking call stack integrity.
This is the most visually distinctive pattern.

Indirect syscalls — CallTrace begins with ntdll.dll, mimicking
legitimate behavior. However, the injector's memory offsets appear
mid-chain before returning to kernel32.dll and ntdll.dll at the bottom.
The jump into ntdll for the syscall instruction is visible in the trace.

The progression from classic to indirect represents a deliberate attempt
to make the CallTrace look increasingly legitimate. Indirect syscalls
nearly succeed — but the injector cannot hide its own call frames
entirely from Sysmon's stack walk.

---

## Finding 4 — Direct Syscalls Produce a Two-Event EID 10 Signature

The direct syscall injector uses WTSEnumerateProcessesA to find the target
PID. This generates a first EID 10 event with GrantedAccess 0x1000 and
a clean CallTrace through WINSTA.dll and WTSAPI32.dll — indistinguishable
from legitimate session management software.

The actual injection then generates a second EID 10 from the same
SourceProcessId with GrantedAccess 0x103A and the broken CallTrace.

This two-event sequence from the same process is a distinctive signature
for this class of injector. Correlating both events within a short time
window from the same SourceProcessId produces a higher-confidence detection
than either event alone.

---

## Finding 5 — StartModule - is a Strong Classic Injection Indicator

EID 8 includes a StartModule field identifying which module the new remote
thread starts executing from. For classic injection, the thread starts
from shellcode written into allocated memory — memory that has no associated
module name. Sysmon logs this as StartModule `-`.

This is a clean, low-noise indicator. Legitimate software that creates
remote threads (debuggers, security tools) almost always starts threads
from within a named, signed module. A StartModule value of `-` combined
with a non-system SourceImage is a strong signal worth alerting on.

---

## Telemetry Gaps Identified

### Gap 1 — No UNKNOWN in CallTrace on Windows 10


The original detection hypothesis assumed direct syscalls would produce
`UNKNOWN` entries in the CallTrace field. This did not occur on Windows 10
x64. The CallTrace showed the injector's own module path and offsets instead.

Detection rules relying on `UNKNOWN` as the primary direct syscall indicator
may miss this technique on modern Windows versions. The more reliable
indicator is injector memory offsets appearing at the top of the CallTrace.

### Gap 2 — Sysmon Cannot Distinguish Indirect from Legitimate ntdll Calls

For indirect syscalls, Sysmon sees the syscall instruction executing inside
ntdll.dll's memory space — which is exactly what legitimate API calls look
like. The only distinguishing feature available to Sysmon is the injector's
call frames mid-chain, which require knowing what constitutes a suspicious
SourceImage path.

In a real environment where the injector is renamed or masquerades as a
legitimate binary, this gap becomes significant. Kernel-level ETW-ti
telemetry or a commercial EDR with call stack validation would be required
for confident detection.

### Gap 3 — No Memory Allocation Visibility

Sysmon does not capture VirtualAllocEx or NtAllocateVirtualMemory calls.
The memory allocation phase of injection — where PAGE_EXECUTE_READWRITE
memory is allocated in the target process — generates no telemetry.
This is a blind spot that allows the setup phase of injection to proceed
undetected.


---

## Sigma Rules

Three Sigma rules were developed and validated against real telemetry

 Rule  File  Confidence 
 ---  ---  --- 
 Classic WinAPI Injection  win_classic_win32_injection.yml  High 
 Direct Syscall Injection  win_direct_syscall_injection.yml  Medium 
 Indirect Syscall Injection  win_indirect_syscall_injection.yml  Medium 

All rules use field values derived from real observed telemetry,
not theoretical values from documentation.