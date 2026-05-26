# Windows Internals Crash Course for Process Injection

## Introduction

When exploring process injection techniques, it is crucial to understand the underlying Windows internals. This document provides an elite crash course on essential concepts, including user mode and kernel mode, processes and threads, and the role of `ntdll.dll` and system calls. This foundational knowledge will then be applied to explain three prominent injection techniques mapped to MITRE ATT&CK T1055: Classic Win32 API Injection, Direct System Calls, and Indirect System Calls. Furthermore, we will dive into how telemetry tools like Sysmon detect these techniques and where their blind spots lie.

## 1. User Mode and Kernel Mode

Windows operates with two primary execution modes: **User Mode** and **Kernel Mode**. This distinction is fundamental to system security and stability [1].

### User Mode

User mode is the less privileged execution environment where applications and most user-level code run. In user mode, code has restricted access to system resources, hardware, and operating system data. Any attempt by a user-mode application to directly access these protected resources results in an exception, which typically leads to the termination of the offending process. This isolation prevents applications from crashing the entire operating system [1].

### Kernel Mode

Kernel mode is the highly privileged execution environment where the operating system kernel, device drivers, and other critical system components operate. Code running in kernel mode has unrestricted access to all system resources, including hardware, memory, and operating system data. While this level of access is necessary for the operating system's functionality, it also carries significant risk. An unhandled exception in kernel mode can lead to a system crash, commonly known as the Blue Screen of Death (BSOD) [1].

### Transitioning Between Modes

User-mode threads frequently need to perform operations that require kernel-mode privileges, such as accessing files, managing memory, or interacting with hardware. To do this, a user-mode application makes a request to the operating system through an Application Programming Interface (API). The operating system then handles this request by transitioning the thread into kernel mode, performing the requested operation, and then returning control and results to the user-mode application [1].

## 2. Processes and Threads

### Processes

A **process** in Windows is a management object that provides the necessary resources for a program to execute. It acts as a container for various data structures and resources required by an application. Key components of a process include [1]:

*   **Virtual Address Space**: A private memory region where the process's code, data, and dynamic libraries are loaded.
*   **Executable File (Image)**: The initial code and data (e.g., `main` function) that starts the application.
*   **Private Handle Table**: A table containing handles to various kernel objects (e.g., files, registry keys, synchronization objects) that are specific to that process. Handles are numerical identifiers that allow the process to interact with these objects. The private nature of this table ensures that one process cannot directly use handles belonging to another process, enforcing process isolation.
*   **Security Context**: Defines the security identity of the process, determining its privileges and permissions when accessing system resources.

It is important to note that a process itself does not execute code; rather, it provides the environment for code execution.

### Threads

**Threads** are the actual entities that execute code within a process. Every process has at least one primary thread, and it can create additional threads to perform tasks concurrently. Threads share the process's virtual address space and other resources but maintain their own execution context, including a program counter, registers, and a stack. When a process is created, an initial thread is always created to begin executing the program's entry point [1].

## 3. `ntdll.dll` and System Calls

### `ntdll.dll`

`ntdll.dll` is a crucial dynamic-link library in Windows that serves as an interface between user-mode applications and the Windows kernel. It exports a set of functions known as **Native API** functions, which are low-level, undocumented functions that directly interact with the kernel. These functions are often prefixed with `Nt` or `Zw` (e.g., `NtCreateFile`, `ZwAllocateVirtualMemory`).

When a high-level Win32 API function (e.g., `CreateFile`) is called by a user-mode application, it typically makes an internal call to a corresponding Native API function in `ntdll.dll`. This `ntdll.dll` function then prepares the necessary parameters and triggers a **system call** to transition into kernel mode and execute the requested operation.

### System Calls (Syscalls)

A system call is the mechanism by which a user-mode program requests a service from the operating system kernel. This transition from user mode to kernel mode is a carefully controlled process to maintain system stability and security. On x64 Windows systems, system calls are typically initiated using the `syscall` instruction.

Each Native API function in `ntdll.dll` has a unique **system call number** (or syscall ID) associated with it. This ID identifies the specific kernel service being requested. When the `syscall` instruction is executed, the syscall ID and other parameters are passed to the kernel, which then dispatches the request to the appropriate kernel function.

## 4. Process Injection Techniques & Sysmon Telemetry

Process injection techniques (MITRE ATT&CK T1055) involve executing arbitrary code within the address space of another live process. These techniques are often used by malware to evade detection, elevate privileges, or maintain persistence. We will examine three common approaches and how they manifest in Sysmon telemetry.

### 4.1. Classic Win32 API Injection (T1055.001)

Classic Win32 API injection typically involves using a sequence of high-level Win32 API functions to inject and execute code in a target process. The general workflow is as follows:

1.  **Open Target Process**: Obtain a handle to the target process using `OpenProcess` with appropriate access rights.
2.  **Allocate Memory**: Allocate memory within the target process's virtual address space using `VirtualAllocEx`.
3.  **Write Payload**: Write the malicious code (shellcode or a DLL path) into the allocated memory using `WriteProcessMemory`.
4.  **Execute Payload**: Create a remote thread in the target process to execute the injected code. This is often done using `CreateRemoteThread`, with the starting address pointing to the injected code or a function like `LoadLibraryA` (if injecting a DLL).

**Internals & EDR Hooking**: This method relies entirely on documented Win32 APIs. While effective, EDR solutions can easily hook these APIs (e.g., `OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`) in user-mode to detect and prevent malicious activity. When these APIs are called, they eventually lead to `ntdll.dll` functions and system calls, but the EDR can intercept them at the higher-level API layer.

**Hypothesis A: Classic Injection Detection**
*   **Expectation**: Sysmon will generate Event ID 10 (ProcessAccess) and Event ID 8 (CreateRemoteThread) with clear, traceable call stacks.
*   **Detection Logic**: Look for `SourceImage` (the injector) accessing `TargetImage` (the victim) with high-access rights (e.g., `0x1F1FFF` or `0x143A`) followed by a remote thread creation. The `CallTrace` will show a normal progression through known Windows APIs (e.g., `kernel32.dll` -> `ntdll.dll`).

### 4.2. Direct System Calls

Direct system calls involve bypassing the high-level Win32 APIs and `ntdll.dll` stubs to directly invoke the `syscall` instruction. The goal is to avoid API hooking by EDRs that monitor calls to `kernel32.dll` or `ntdll.dll` functions. The workflow typically involves:

1.  **Resolve Syscall ID**: Determine the system call ID for the desired Native API function (e.g., `NtAllocateVirtualMemory`). This can be done by parsing `ntdll.dll` in memory or on disk.
2.  **Prepare Parameters**: Set up the function parameters in the appropriate registers according to the Windows x64 calling convention.
3.  **Execute `syscall` Instruction**: Directly execute the `syscall` instruction with the resolved syscall ID and parameters.

**Internals & Call Stack Integrity**: By directly executing the `syscall` instruction, attackers attempt to circumvent user-mode hooks placed by EDRs on `ntdll.dll` functions. However, EDRs can still detect this by monitoring the `syscall` instruction itself or by analyzing the call stack. If the `syscall` instruction is executed from an unexpected memory region (i.e., not from `ntdll.dll`), it can be flagged as suspicious [2].

**Hypothesis B: Direct Syscalls Detection**
*   **Expectation**: Sysmon Event ID 10 will show a `CallTrace` that does not begin with `ntdll.dll` or `wow64.dll`.
*   **Detection Logic**: Filter Event ID 10 for `CallTrace` patterns containing `UNKNOWN` or addresses that are not mapped to a loaded module. This indicates that the syscall was invoked directly from the injector's memory space, breaking Call Stack Integrity.

### 4.3. Indirect System Calls

Indirect system calls are an evolution of direct system calls, designed to further evade EDR detection by making the `syscall` instruction appear to originate from legitimate `ntdll.dll` memory. This technique aims to address the EDR detection of direct syscalls based on call stack analysis [2].

The core idea is to find the `syscall` instruction within the legitimate `ntdll.dll` module in memory and then jump to it. The workflow is similar to direct syscalls but with a crucial difference [2]:

1.  **Resolve Syscall ID and `syscall` Instruction Address**: Obtain the syscall ID for the Native API function, and critically, also find the address of the `syscall` instruction within the corresponding `ntdll.dll` function stub.
2.  **Prepare Parameters**: Set up the function parameters in registers.
3.  **Jump to `syscall` Instruction**: Instead of directly executing `syscall` from attacker-controlled memory, the malicious code performs an unconditional jump (`jmp`) to the legitimate `syscall` instruction within `ntdll.dll`.

**Internals & Detection Difficulty**: The key advantage of indirect syscalls is that both the `syscall` instruction and the subsequent `ret` (return) instruction are executed within the memory space of `ntdll.dll`. This makes the call stack appear legitimate to EDRs that perform stack-walking to identify anomalous `syscall` origins. By ensuring the execution flow remains within `ntdll.dll` for the critical `syscall` and `ret` operations, indirect syscalls make it significantly harder for EDRs to distinguish between legitimate and malicious system calls based on memory region analysis [2].

**Hypothesis C: Indirect Syscalls Detection**
*   **Expectation**: Sysmon Event ID 10 will show a `CallTrace` that *does* begin with `ntdll.dll`, successfully mimicking legitimate behavior.
*   **Detection Logic**: Detection is significantly harder with Sysmon alone. It may require looking for anomalous `SourceUser` or `SourceImage` behavior, cross-referencing with Event ID 7 (Image Load) for missing DLLs, or relying on kernel-level ETW-ti telemetry to identify the true origin of the call.

## 5. Telemetry Expectations Matrix

To provide a clear validation checklist for detection engineers, the following matrix outlines the expected Sysmon telemetry for each injection technique:

| Technique | Event ID 1 | Event ID 8 | Event ID 10 | CallTrace Integrity | Expected Visibility |
| :------------------------ | :--------- | :--------- | :---------- | :------------------ | :------------------ |
| Classic WinAPI Injection | YES | YES | YES | Normal | HIGH |
| Direct Syscalls | YES | POSSIBLE NO | YES | Broken/Suspicious | MEDIUM |
| Indirect Syscalls | YES | NO | YES | Legitimate-looking | LOW |

### Why Event ID 10 Matters

Unlike Event ID 8, which depends on remote thread creation telemetry, Event ID 10 captures inter-process access behavior that remains necessary even when syscall execution methods evolve. Regardless of whether attackers use Win32 APIs, direct syscalls, or indirect syscalls, the injector must still acquire privileged access to the target process to manipulate memory. This makes Event ID 10 a crucial anchor for behavioral detection.

## 6. Telemetry Gaps & Blind Spots

Understanding where Sysmon falls short is just as important as knowing what it can detect. Advanced adversaries actively exploit these gaps.

| Gap Type | Description | Impact on Sysmon |
| :--- | :--- | :--- |
| **Stack Spoofing** | Attackers can overwrite the call stack in memory before the telemetry is captured. | Can make Direct Syscalls look like Indirect or even Classic injection, confusing analysts and bypassing simple `CallTrace` rules. |
| **Module Stomping** | Injecting code into legitimate DLL memory space (e.g., DLL Hollowing). | Sysmon Event ID 10 may show a legitimate module in the `CallTrace`, but the offset will be anomalous. |
| **Kernel-Mode Callbacks** | Sysmon relies on kernel callbacks (e.g., `PsSetCreateThreadNotifyRoutine`). | If an attacker can disable or bypass these callbacks (e.g., via Bring Your Own Vulnerable Driver - BYOVD), Sysmon goes completely blind. |
| **ETW-ti Limitations** | Sysmon does not consume all ETW-ti (Threat Intelligence) events by default. | Advanced "Indirect" techniques that use `NtTestAlert` or APCs might have limited visibility without additional ETW tracing. |

## 7. Research Methodology

This project follows a controlled adversary emulation methodology to validate detection capabilities against evolving injection techniques:

1.  **Establish Baseline Telemetry**: Begin with classic Win32 injection, observing Sysmon visibility and potential Splunk correlations.
2.  **Direct Syscall Implementation**: Replace Win32 APIs with direct syscalls, documenting changes in telemetry visibility.
3.  **Indirect Syscall Implementation**: Upgrade the injector to indirect syscalls with dynamic resolution, meticulously documenting telemetry blind spots.
4.  **Behavioral Detection Engineering**: Engineer behavioral detections around surviving artifacts.
5.  **Measure Reliability**: Quantify detection reliability and false positives.

This methodology emphasizes isolating variables by using the same target process and payload, with only the delivery mechanism changing. This scientific rigor ensures that observed telemetry changes are directly attributable to the injection technique, enhancing the credibility of the research.

## 8. Detection Philosophy

Our detection philosophy intentionally shifts from traditional signature-based approaches to robust behavioral correlation.

### Signature Detection

Signature-based detection relies on identifying known patterns such as syscall stub signatures, API hooks, opcode patterns, or other static indicators. While effective against known threats, its primary weakness is its susceptibility to mutation; attackers can rapidly alter implementations to bypass static signatures.

### Behavioral Detection

Behavioral detection focuses on the underlying actions and characteristics of malicious activity, such as process access behavior, privilege escalation patterns, anomalous memory operations, and unexpected process relationships. Its strength lies in its resilience: attackers must still perform core malicious behaviors, making these actions harder to obscure and providing more durable detection opportunities.

## 9. Sysmon Event Rationale

Understanding the purpose and relevance of specific Sysmon Event IDs is critical for effective detection engineering:

| Event ID | Purpose | Relevance |
| :------- | :------------------ | :---------------------------------- |
| 1 | Process Creation | Identify injector execution |
| 7 | Image Load | Detect anomalous module behavior |
| 8 | CreateRemoteThread | Classic injection detection |
| 10 | ProcessAccess | Behavioral detection anchor |

Event ID 10 becomes the centerpiece of our detection strategy due to its ability to capture the fundamental act of inter-process memory manipulation, a prerequisite for all injection techniques.

## 10. Experimental Constraints

To ensure research credibility and contextualize findings, it is important to state the experimental constraints and assumptions:

*   **Environment**: Tests are performed in an isolated Windows VM.
*   **Sysmon Version**: Specific Sysmon version X (to be specified).
*   **Operating System**: Windows 11 x64.
*   **Telemetry Scope**: User-mode telemetry only.
*   **EDR Presence**: No kernel EDR drivers are assumed to be active during initial testing.
*   **Stack Spoofing Countermeasures**: No stack-spoofing countermeasures are enabled by default.

It is important to note that findings may differ significantly in environments with active kernel-mode EDRs or modern commercial EDRs that employ proprietary telemetry and advanced detection mechanisms.

## 11. ATT&CK Mapping

Mapping injection techniques to MITRE ATT&CK provides a standardized framework for understanding adversary tactics and techniques, crucial for both red and blue teams:

| Technique | ATT&CK ID | Description |
| :-------------------- | :---------- | :------------------------------------ |
| Process Injection | T1055 | Memory execution inside remote process |
| Native API | T1106 | `Nt*` syscall usage |
| Dynamic API Resolution | T1027.007 | Runtime syscall resolution |
| APC Injection | T1055.004 | Asynchronous execution |
| Process Hollowing | T1055.012 | Image replacement |

This mapping helps in categorizing and communicating the observed behaviors within a widely recognized threat intelligence framework.

## 12. Planned Detection Correlation Logic

The detection strategy will leverage behavioral correlation to identify stealthy injection attempts. The goal is to identify stealth injection even when thread creation telemetry (Event ID 8) is absent.

Key elements for correlation will include:

*   **Event ID 10 High-Privilege Access**: Detecting `ProcessAccess` events with high access rights.
*   **Absence of Event ID 8**: Noting the lack of `CreateRemoteThread` events, which is indicative of more advanced injection methods.
*   **Suspicious CallTrace Patterns**: Analyzing `CallTrace` for `UNKNOWN` modules or unexpected origins.
*   **Short-Lived Injector Process Activity**: Identifying processes that perform injection-related actions and then terminate quickly.
*   **Anomalous Source-Target Process Relationships**: Detecting unusual interactions between processes.

This correlation logic directly sets the stage for advanced Splunk queries and behavioral analytics, moving beyond simple signature matching to detect sophisticated threats.
