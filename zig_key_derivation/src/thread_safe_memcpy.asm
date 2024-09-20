global unlock_thread 

section .text

unlock_thread:
  ;rcx dest
  
  mov rax, 0x9090909090909090

  lock xchg [rcx], rax
  xor eax, eax
  ret
