
; Assemble with:
;   nasm -f bin shellcode_artful.asm -o shellcode_artful.bin


BITS 64


stub_start:
    sub  rsp, 0x28
    and  rsp, 0xFFFFFFFFFFFFFFF0

    lea  rdx, [rel str_LoadLibraryA]        
    lea  rcx, [rel str_KERNEL32]            
    call helper                             
    mov  r15, rax                        
    
    lea  rcx, [rel str_USER32]              
    call r15

    lea  rdx, [rel str_MessageBoxA]         
    lea  rcx, [rel str_USER32]              
    call helper                             

    xor  r9d,  r9d                          
    lea  r8,   [rel str_title]            
    lea  rdx,  [rel str_message]            
    xor  ecx,  ecx                       
    call rax

    lea  rdx, [rel str_ExitProcess]          
    lea  rcx, [rel str_KERNEL32]            
    call helper                             
    xor  ecx, ecx
    call rax


str_KERNEL32:     db "KERNEL32.DLL",  0   
str_LoadLibraryA: db "LoadLibraryA",  0   
str_USER32:       db "USER32.DLL",    0   
str_MessageBoxA:  db "MessageBoxA",   0   
str_message:      db "Nader Ayman",   0   
str_title:        db "Artful Dodger", 0   
str_ExitProcess:  db "ExitProcess",   0   


helper:
    db 0x48, 0x83, 0xEC, 0x28           ; sub  rsp, 0x28
    db 0x65, 0x4C, 0x8B, 0x04, 0x25    ; mov  r8, gs:[0x60]    (PEB)
    db 0x60, 0x00, 0x00, 0x00
    db 0x4D, 0x8B, 0x40, 0x18           ; mov  r8, [r8+0x18]   (Ldr)
    db 0x4D, 0x8D, 0x60, 0x10           ; lea  r12, [r8+0x10]  (sentinel)
    db 0x4D, 0x8B, 0x04, 0x24           ; mov  r8, [r12]       (first entry)
    db 0xFC                             ; cld

    ; walk_modules:
    db 0x49, 0x8B, 0x78, 0x60           ; mov  rdi, [r8+0x60]  (BaseDllName.Buffer)
    db 0x48, 0x8B, 0xF1                 ; mov  rsi, rcx

    ; cmp_loop:
    db 0xAC                             ; lodsb
    db 0x84, 0xC0                       ; test al, al
    db 0x74, 0x26                       ; jz   found_module
    db 0x8A, 0x27                       ; mov  ah, [rdi]
    db 0x80, 0xFC, 0x61                 ; cmp  ah, 'a'
    db 0x7C, 0x03                       ; jl   no_lower
    db 0x80, 0xEC, 0x20                 ; sub  ah, 0x20

    ; no_lower:
    db 0x3A, 0xE0                       ; cmp  ah, al
    db 0x75, 0x08                       ; jne  next_module
    db 0x48, 0xFF, 0xC7                 ; inc  rdi
    db 0x48, 0xFF, 0xC7                 ; inc  rdi   (UTF-16 skip)
    db 0xEB, 0xE5                       ; jmp  cmp_loop

    ; next_module:
    db 0x4D, 0x8B, 0x00                 ; mov  r8, [r8]
    db 0x4D, 0x3B, 0xC4                 ; cmp  r8, r12
    db 0x75, 0xD6                       ; jne  walk_modules
    db 0x48, 0x33, 0xC0                 ; xor  rax, rax
    db 0xE9, 0xA7, 0x00, 0x00, 0x00     ; jmp  done

    ; found_module:
    db 0x49, 0x8B, 0x58, 0x30           ; mov  rbx, [r8+0x30]  (DllBase)
    db 0x44, 0x8B, 0x4B, 0x3C           ; mov  r9d, [rbx+0x3C] (e_lfanew)
    db 0x4C, 0x03, 0xCB                 ; add  r9, rbx
    db 0x49, 0x81, 0xC1, 0x88, 0x00, 0x00, 0x00  ; add r9, 0x88
    db 0x45, 0x8B, 0x29                 ; mov  r13d, [r9]
    db 0x4D, 0x85, 0xED                 ; test r13, r13
    db 0x75, 0x08                       ; jnz  has_exports
    db 0x48, 0x33, 0xC0                 ; xor  rax, rax
    db 0xE9, 0x85, 0x00, 0x00, 0x00     ; jmp  done

    ; has_exports:
    db 0x4E, 0x8D, 0x04, 0x2B           ; lea  r8, [rbx+r13]
    db 0x45, 0x8B, 0x71, 0x04           ; mov  r14d, [r8+4]
    db 0x4D, 0x03, 0xF5                 ; add  r14, r13
    db 0x41, 0x8B, 0x48, 0x18           ; mov  ecx, [r8+0x18]  (NumberOfNames)
    db 0x45, 0x8B, 0x50, 0x20           ; mov  r10d, [r8+0x20] (AddressOfNames RVA)
    db 0x4C, 0x03, 0xD3                 ; add  r10, rbx

    ; name_loop:
    db 0xFF, 0xC9                       ; dec  ecx
    db 0x4D, 0x8D, 0x0C, 0x8A          ; lea  r9, [r10+rcx*4]
    db 0x41, 0x8B, 0x39                 ; mov  edi, [r9]
    db 0x48, 0x03, 0xFB                 ; add  rdi, rbx
    db 0x48, 0x8B, 0xF2                 ; mov  rsi, rdx

    ; str_cmp:
    db 0xA6                             ; cmpsb
    db 0x75, 0x08                       ; jne  no_match
    db 0x8A, 0x06                       ; mov  al, [rsi]
    db 0x84, 0xC0                       ; test al, al
    db 0x74, 0x09                       ; jz   name_match
    db 0xEB, 0xF5                       ; jmp  str_cmp

    ; no_match:
    db 0xE2, 0xE6                       ; loop name_loop
    db 0x48, 0x33, 0xC0                 ; xor  rax, rax
    db 0xEB, 0x4E                       ; jmp  done

    ; name_match:
    db 0x45, 0x8B, 0x48, 0x24          ; mov  r9d, [r8+0x24]  (AddressOfNameOrdinals RVA)
    db 0x4C, 0x03, 0xCB                 ; add  r9, rbx
    db 0x66, 0x41, 0x8B, 0x0C, 0x49    ; mov  cx, [r9+rcx*2]
    db 0x45, 0x8B, 0x48, 0x1C          ; mov  r9d, [r8+0x1C]  (AddressOfFunctions RVA)
    db 0x4C, 0x03, 0xCB                 ; add  r9, rbx
    db 0x41, 0x8B, 0x04, 0x89          ; mov  eax, [r9+rcx*4]
    db 0x49, 0x3B, 0xC5                 ; cmp  rax, r13
    db 0x7C, 0x2F                       ; jl   not_forwarded
    db 0x49, 0x3B, 0xC6                 ; cmp  rax, r14
    db 0x73, 0x2A                       ; jae  not_forwarded

    ; forwarded:
    db 0x48, 0x8D, 0x34, 0x18          ; lea  rsi, [rax+rbx]
    db 0x48, 0x8D, 0x7C, 0x24, 0x30   ; lea  rdi, [rsp+0x30]
    db 0x4C, 0x8B, 0xE7                ; mov  r12, rdi

    ; copy_fwd:
    db 0xA4                             ; movsb
    db 0x80, 0x3E, 0x2E                 ; cmp  byte [rsi], '.'
    db 0x75, 0xFA                       ; jne  copy_fwd
    db 0xA4                             ; movsb
    db 0xC7, 0x07, 0x44, 0x4C, 0x4C, 0x00  ; mov dword [rdi], "DLL\0"
    db 0x49, 0x8B, 0xCC                ; mov  rcx, r12
    db 0x41, 0xFF, 0xD7                ; call r15
    db 0x49, 0x8B, 0xCC                ; mov  rcx, r12
    db 0x48, 0x8B, 0xD6                ; mov  rdx, rsi
    db 0xE9, 0x14, 0xFF, 0xFF, 0xFF    ; jmp  helper

    ; not_forwarded:
    db 0x48, 0x03, 0xC3                ; add  rax, rbx
    ; done:
    db 0x48, 0x83, 0xC4, 0x28         ; add  rsp, 0x28
    db 0xC3                            ; ret
