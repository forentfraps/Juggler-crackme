global appendByte2Rip

section .text

  appendByte2Rip:
    pop r11
    add r11, 1
    jmp r11
