# Detection Gaps & Blind Spots

The gaps below are specific to Sysmon user-mode telemetry. Some can be
partially addressed with ETW-ti providers or commercial EDR solutions.
None of them are fixable with Sysmon alone.

---

## Gap 1 — Memory Allocation Phase is Invisible

**What Sysmon misses:** VirtualAllocEx and NtAllocateVirtualMemory calls.

Every injection technique requires allocating executable memory in the
target process before writing the payload. This is where
PAGE_EXECUTE_READWRITE memory regions are created — one of the most
suspicious memory protection combinations in Windows.

Sysmon has no event that captures memory allocation operations. The
entire setup phase of injection proceeds without generating any telemetry.
By the time EID 10 fires for ProcessAccess, the memory has already been
allocated and the payload may already be written.

**What helps:** Some commercial EDRs hook NtAllocateVirtualMemory at the
kernel level and alert on PAGE_EXECUTE_READWRITE allocations in remote
processes. ETW providers like Microsoft-Windows-Kernel-Memory can capture
this but require additional configuration beyond Sysmon.

---

## Gap 2 — WriteProcessMemory Leaves No Trace

**What Sysmon misses:** NtWriteVirtualMemory and WriteProcessMemory calls.

After allocating memory, the injector writes the payload into the target
process. This write operation — the moment malicious code enters the
target process — generates no Sysmon event.

The EID 10 ProcessAccess event captures that access happened and with
what rights, but does not capture what was written or where. Sysmon
sees the door opening, not what walked through it.

**What helps:** Memory forensics tools can identify injected shellcode
after the fact by scanning for executable memory regions that are not
backed by a file on disk. This is a reactive capability, not a real-time
detection.

---

## Gap 3 — Stack Spoofing Defeats CallTrace Analysis

**What Sysmon misses:** Manipulated call stacks before telemetry capture.

The CallTrace field in EID 10 is populated by walking the thread's call
stack at the moment the ProcessAccess event is generated. An attacker
who overwrites the stack before this capture happens can make any
injection technique look like any other.

Stack spoofing tools can make direct syscalls appear to originate from
ntdll.dll, making them visually identical to indirect syscalls or
legitimate API calls. The entire CallTrace-based detection strategy
in this project can be defeated by a sufficiently capable adversary
who implements stack spoofing.

**What helps:** Kernel-level ETW-ti (Threat Intelligence) providers
capture the true syscall origin before the stack can be manipulated.
This requires Windows Defender Credential Guard or a commercial EDR
with kernel callbacks at a lower level than Sysmon operates.

---

## Gap 4 — BYOVD Kills Sysmon Entirely

**What Sysmon misses:** Everything, if the driver is disabled.

Sysmon operates as a kernel driver (SysmonDrv) that registers callbacks
with the Windows kernel — PsSetCreateProcessNotifyRoutine,
PsSetCreateThreadNotifyRoutine, and others. These callbacks are how
Sysmon receives notification of process and thread events.

A Bring Your Own Vulnerable Driver (BYOVD) attack loads a legitimate
but vulnerable signed driver and exploits it to execute kernel-mode code.
From kernel mode, an attacker can unregister Sysmon's callbacks, effectively
blinding it completely. No callbacks means no events. Sysmon continues
running and appears healthy, but captures nothing.

This is not a theoretical attack. BYOVD has been observed in the wild
from multiple threat actor groups including Lazarus Group.

**What helps:** Vulnerable driver blocklists (Microsoft's recommended
driver block rules), Hypervisor Protected Code Integrity (HVCI), and
monitoring for unexpected driver loads via EID 6. None of these fully
prevent a determined attacker with physical or administrative access.

---

## Gap 5 — Module Stomping Bypasses ImageLoad Detection

**What Sysmon misses:** Code execution within legitimate DLL memory.

Module stomping involves injecting code into the memory space of an
already-loaded legitimate DLL rather than allocating new executable
memory. The payload overwrites part of the DLL's code section and
executes from there.

From Sysmon's perspective, EID 7 shows the legitimate DLL was loaded —
which is normal. EID 10 shows the injector accessed the target process —
suspicious, but the CallTrace may show a legitimate DLL path because
execution happens within that DLL's memory space. The offset within
the DLL will be anomalous, but this requires deep knowledge of normal
DLL code section sizes to detect.

**What helps:** Scanning for memory regions where the on-disk DLL hash
does not match the in-memory content. This is a specialized capability
not available in Sysmon.

---

## Gap 6 — Process Hollowing Has Limited Sysmon Visibility

**What Sysmon misses:** The image replacement operation itself.

Process hollowing creates a suspended legitimate process, unmaps its
original executable image, and replaces it with malicious code before
resuming execution. The running process appears to be notepad.exe or
svchost.exe but is executing attacker code.

Sysmon EID 1 captures the process creation with the legitimate binary
name. EID 25 (ProcessTampering) was added in newer Sysmon versions
specifically to catch this, but requires explicit configuration and
has higher false positive rates than EID 10.

**What helps:** EID 25 with careful tuning, combined with hash comparison
between the process image on disk and in memory.

---

## Summary — Coverage Map

| Attack Phase | Sysmon Coverage | Gap Severity |
| :--- | :--- | :--- |
| Injector process launch | EID 1 — full coverage | None |
| Memory allocation | No coverage | High |
| Payload write | No coverage | High |
| Thread/process access | EID 10 — full coverage | Low |
| Thread creation | EID 8 — partial coverage | Medium |
| DLL loads | EID 7 — partial coverage | Medium |
| Stack spoofing | No coverage | High |
| Driver-level evasion | No coverage | Critical |
| Module stomping | Partial via EID 7 offset analysis | High |


---

## Honest Assessment of This Project's Detection Coverage

The three Sigma rules in this project provide reliable detection for
injection techniques executed from unsigned binaries running from
user-writable paths, against common target processes, without stack
spoofing, on systems where Sysmon is running and uncorrupted.

That covers a meaningful portion of real-world injection attempts —
particularly commodity malware and less sophisticated threat actors.
It does not cover nation-state level adversaries who implement stack
spoofing, BYOVD, or kernel-level evasion.

