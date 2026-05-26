# False Positive Tuning Guide

This document covers real false positive scenarios observed during controlled
adversary emulation of T1055 process injection techniques on Windows 10 x64
with Sysmon v15.20. Every scenario here was encountered during actual testing,
not sourced from generic documentation.

---

## The Core Problem

Process injection detection sits at a difficult intersection — the same Windows
APIs and kernel mechanisms used by malware are also used by legitimate software
every day. Debuggers open process handles. Security tools create remote threads.
Antivirus engines read process memory. Without careful tuning, your detection
rules will fire constantly on legitimate activity and get ignored or disabled.

The goal is not zero false positives — that's impossible. The goal is
**high-confidence alerts that analysts actually investigate.**

---

## Real False Positives Observed During Testing

### 1. WTSEnumerateProcessesA Generating EID 10

**What happened:** The direct syscall injector uses `WTSEnumerateProcessesA`
to find the target PID. This generated an EID 10 event with a completely
clean-looking CallTrace through legitimate Windows DLLs:

```
ntdll.dll → WINSTA.dll → WTSAPI32.dll → injector.exe
GrantedAccess: 0x1000
```

**Why it matters:** On its own, this event is indistinguishable from any
legitimate application using WTS APIs for session or process enumeration.
Remote desktop management tools, session monitoring software, and some
antivirus products generate identical telemetry.

**Tuning approach:** Do not alert on this event alone. Correlate with a
second EID 10 from the same SourceProcessId within a short time window
showing a higher GrantedAccess mask. The combination is the signal.

---

### 2. Unexpected EID 8 for Indirect Syscalls

**What happened:** Indirect syscalls generated EID 8 (CreateRemoteThread)
during testing despite documentation stating they should not. This means
a detection rule tuned to fire on EID 8 absence for indirect syscalls
will produce incorrect results on Windows 10 with Sysmon v15.20.

**Why it matters:** If your detection logic assumes indirect syscalls
never produce EID 8, you will miss them entirely on systems where
Sysmon captures NtCreateThreadEx regardless of invocation method.

**Tuning approach:** Do not rely on EID 8 absence as a detection signal
for indirect syscalls. Use CallTrace pattern analysis instead — specifically
looking for ntdll.dll at the top with injector memory offsets mid-chain.

---

### 3. Multiple EID 10 Events Per Injection Run

**What happened:** Each injector run produced multiple EID 10 events
targeting the same process — some from legitimate Windows internals,
some from the actual injection. Without filtering by SourceImage,
the noise makes triage difficult.

**Why it matters:** Alerting on every EID 10 targeting notepad.exe or
explorer.exe will generate enormous volume in production environments
where these processes are constantly accessed by legitimate software.

**Tuning approach:** Scope EID 10 rules to suspicious SourceImage paths
first — executables running from `C:\Users\`, `C:\Temp\`, `C:\ProgramData\`,
or other user-writable locations. This eliminates the majority of
system-generated noise while preserving detection coverage.

---

### 4. Windows Defender Generating EID 10 Against lsass.exe

**What happened:** Defender's real-time protection engine accessed lsass.exe
continuously during testing, generating high-volume EID 10 events with
elevated GrantedAccess masks identical to what credential dumping tools use.

**Why it matters:** Without excluding Defender's known signed binaries,
lsass.exe-targeted rules will fire constantly in any production environment
with Defender enabled.

**Tuning approach:** Exclude by SourceImage path AND signature:
```
C:\Program Files\Windows Defender\
C:\ProgramData\Microsoft\Windows Defender\
```
Do not exclude by process name alone — malware can rename itself
to `MsMpEng.exe`. Always verify the full signed path.

---

## Tuning by Technique

### Classic WinAPI Injection

The strongest signal is EID 8 with `StartModule: -` combined with
EID 10 showing high GrantedAccess. False positives come from:

- **Visual Studio debugger** — creates remote threads during attach operations.
  Whitelist by path: `C:\Program Files\Microsoft Visual Studio\`
- **Process Monitor / Process Hacker** — legitimate admin tools that open
  process handles with high access rights.
  Whitelist by path and only on known analyst workstations.
- **Game anti-cheat software** — frequently uses CreateRemoteThread for
  legitimate integrity checking. Identify by signed binary verification.

**Recommended filter:**
```yaml
filter_legitimate_tools:
  SourceImage|startswith:
    - 'C:\Program Files\Microsoft Visual Studio\'
    - 'C:\Program Files\Sysinternals\'
  Signed: 'true'
```

---

### Direct Syscalls

False positives are lower here because the broken CallTrace pattern
(injector offsets at the top) is unusual for legitimate software.
However, watch for:

- **Custom internal tooling** running from user directories that makes
  inter-process calls for legitimate automation purposes.
- **Penetration testing frameworks** — Cobalt Strike, Metasploit, and
  similar tools will trigger this rule. This is expected and intended.
- **Some game engines** — Unity and Unreal Engine development builds
  sometimes exhibit unusual CallTrace patterns from their memory managers.

**Recommended filter:**
Add known internal tool paths to the SourceImage exclude list and
document the exception with a justification comment.

---

### Indirect Syscalls

This is the hardest to tune because the ntdll.dll-topped CallTrace
looks legitimate by design. The injector path appearing mid-chain
is the only reliable indicator without ETW-ti telemetry.

False positives come from:

- **Security products with ntdll-based call stacks** — some EDR and
  DLP agents use ntdll directly for their own inter-process operations.
- **JIT-compiled code** — .NET applications and Java programs can
  produce unusual CallTrace patterns that superficially resemble
  indirect syscall signatures.
- **Browser renderer processes** — Chrome and Edge spawn heavily
  sandboxed processes that access each other through unusual call paths.

**Recommended approach:** For indirect syscalls, treat EID 10 CallTrace
analysis as a medium-confidence signal only. Require correlation with
at least one of:
- EID 7 showing unexpected DLL loads into the target process
- EID 1 showing the source process spawned from a suspicious parent
- Process running from a non-standard path



