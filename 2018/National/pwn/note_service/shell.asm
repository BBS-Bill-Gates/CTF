section .text
    global _start

_start:
      xor rax, rax
      xor rdx, rdx
      push rax
      xor rsi, rsi
      mov dword [rbx], 0x68732f2f 
      add rbx, 0x4
      push 0x6e69622f
      pop rcx
      mov [rbx+4], rcx
      push rbx
      push rsp
      pop rdi
      mov al, 59
      int 0x80
