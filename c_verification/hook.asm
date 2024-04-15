global SetWinAddrs
global Starter
section .data
  rtl dq 0
  etwp dq 0
  f dq 0

section .text
align 16
  SetWinAddrs:
    mov rax, rtl
    mov [rax], rcx
    mov rax, etwp
    mov [rax], rdx
    mov rax, f
    mov [rax], r8

    ret
align 16
  Catalyst:
    mov rax, rtl
    mov rax, [rax]
    add rax, 0xd
    push rbx
    sub rsp, 0x20
    push rax
    mov rax, etwp
    mov rax, [rax] 
    xor ecx, ecx
    jmp rax
    ret

align 16
  Starter:
        mov rax, f
    mov rax, [rax]
    call rax
        jmp Catalyst
    ret 





