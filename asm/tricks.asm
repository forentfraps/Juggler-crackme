global appendByte2Rip
global wardenCallback

section .text

  appendByte2Rip:
    pop r11
    add r11, 1
    jmp r11

  wardenCallback:
    
    mov r9, rdx
    mov rax, [r9]
    mov rcx, [r9 + 8]
    mov rdx, [r9 + 16]
    jmp rax
