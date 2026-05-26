# Evasion Testing — Stack Spoofing Analysis

This document explains how stack spoofing defeats the CallTrace-based
detection strategy used in this project, and what would be required to
detect it. No working exploit code is provided — the value here is
understanding the detection boundary, not crossing it.

---

## Why This Folder Exists

The three Sigma rules in this project are built around CallTrace analysis.
That strategy works against unsophisticated injectors. A more capable
adversary who implements stack spoofing can defeat it entirely.

Documenting this is not an admission of failure. It is an honest assessment
of where the detection boundary sits and what lies beyond it. A detection
engineer who claims their rules catch everything is either lying or hasn't
tested against a real adversary.

---

## What Stack Spoofing Is

When Sysmon captures an EID 10 ProcessAccess event, it walks the calling
thread's stack to build the CallTrace field. Stack spoofing manipulates
the call stack in memory before this walk happens, replacing the real
return addresses with fabricated ones pointing to legitimate Windows modules.

The result: a direct syscall that executed entirely from attacker-controlled
memory produces a CallTrace that shows only ntdll.dll and kernel32.dll —
indistinguishable from a legitimate API call.

---

## How It Defeats This Project's Detection

The three detection rules in this project rely on:

**Classic injection** — EID 8 StartModule "-" and high GrantedAccess.
Stack spoofing does not help classic injection because EID 8 is generated
by a different kernel callback that captures the thread start address
before spoofing can occur. Classic injection detection survives.

**Direct syscalls** — Injector memory offsets at the top of CallTrace.
Stack spoofing directly defeats this. After spoofing, the CallTrace
begins with ntdll.dll rather than the injector's own offsets. The
primary indicator disappears entirely.

**Indirect syscalls** — ntdll.dll at top with injector mid-chain.
Stack spoofing can clean the mid-chain injector frames, making the
CallTrace appear completely legitimate. Detection confidence drops
to near zero.

---

## What a Stack Spoofer Does — Conceptually

A stack spoofer typically works in three steps:

**Step 1 — Allocate a fake stack frame.**
The attacker constructs a fake call stack in memory containing return
addresses pointing to legitimate Windows modules at plausible offsets.
These are real addresses within ntdll.dll, kernel32.dll, or other
system libraries — just not the actual call path that was taken.

**Step 2 — Overwrite RSP before the syscall.**
Before executing the syscall instruction, the attacker overwrites the
stack pointer (RSP) to point at the fabricated stack frame. From this
point forward, any stack walk will follow the fake frames.

**Step 3 — Restore RSP after the syscall returns.**
After the kernel returns from the syscall, RSP is restored to the
real stack. Execution continues normally. Sysmon saw only the fake frames.

---

## What Detection Requires

Defeating stack spoofing from a detection perspective requires moving
below the user-mode stack walk that Sysmon performs. Specifically:

**ETW-ti (Threat Intelligence) providers** — Microsoft's kernel-mode
ETW providers capture the true syscall origin at the moment the
`syscall` instruction is executed, before any user-mode stack manipulation
is possible. This data is available to commercial EDR products that
consume ETW-ti but is not exposed through Sysmon.

**Hardware-based call stack validation** — Intel CET (Control-flow
Enforcement Technology) maintains a separate shadow stack that cannot
be modified by user-mode code. Comparing the shadow stack against the
regular stack at syscall time reveals spoofed frames. Requires hardware
support and OS integration.

**Behavioral correlation beyond CallTrace** — Even with a spoofed
CallTrace, other behavioral signals survive. A process that allocates
PAGE_EXECUTE_READWRITE memory in a remote process, writes to it, and
then generates a ProcessAccess event with high GrantedAccess is still
suspicious regardless of what the CallTrace shows. Correlation across
multiple signals raises confidence even when individual signals are
spoofed.

---

## Impact on This Project's Detection Coverage

| Technique | Without Spoofing | With Spoofing |
| :--- | :--- | :--- |
| Classic injection | High confidence | High confidence (EID 8 survives) |
| Direct syscalls | Medium confidence | Low confidence |
| Indirect syscalls | Medium confidence | Very low confidence |

---

## Honest Conclusion

Stack spoofing represents the next layer of the cat-and-mouse game
between adversaries and detection engineers. The rules in this project
are effective against the techniques as implemented. They are not
effective against an adversary who adds stack spoofing on top.

The appropriate response is not to claim the rules are sufficient anyway.
It is to document the gap clearly, understand what additional telemetry
would close it, and be honest with anyone deploying these rules about
what they will and will not catch.

That is what this folder is for.
