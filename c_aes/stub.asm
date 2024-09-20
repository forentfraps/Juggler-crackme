global stub
global EventLoopCallback

section .text

  stub:
    ret

EventLoopCallback:
  jmp rdx
