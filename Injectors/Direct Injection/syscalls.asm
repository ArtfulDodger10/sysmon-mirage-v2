; syscalls.asm - NASM x64, COFF format for MinGW
; Assemble: nasm -f win64 syscalls.asm -o syscalls.o

section .data
    ; External DWORD variables (defined in C)
    extern NtCloseSSN
    extern NtOpenProcessSSN
    extern NtCreateThreadExSSN
    extern NtWriteVirtualMemorySSN
    extern NtWaitForSingleObjectSSN
    extern NtAllocateVirtualMemorySSN

section .text
    default rel                     ; ← RIP-relative addressing by default (fixes warning)
    
    global NtOpenProcess
    global NtAllocateVirtualMemory
    global NtWriteVirtualMemory
    global NtCreateThreadEx
    global NtWaitForSingleObject
    global NtClose

; ─────────────────────────────────────────
NtOpenProcess:
    mov r10, rcx
    mov eax, dword [NtOpenProcessSSN]   ; RIP-relative dereference
    syscall
    ret

NtAllocateVirtualMemory:
    mov r10, rcx
    mov eax, dword [NtAllocateVirtualMemorySSN]
    syscall
    ret

NtWriteVirtualMemory:
    mov r10, rcx
    mov eax, dword [NtWriteVirtualMemorySSN]
    syscall
    ret

NtCreateThreadEx:
    mov r10, rcx
    mov eax, dword [NtCreateThreadExSSN]
    syscall
    ret

NtWaitForSingleObject:
    mov r10, rcx
    mov eax, dword [NtWaitForSingleObjectSSN]
    syscall
    ret

NtClose:
    mov r10, rcx
    mov eax, dword [NtCloseSSN]
    syscall
    ret