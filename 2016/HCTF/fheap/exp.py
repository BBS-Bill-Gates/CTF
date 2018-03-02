from pwn import *

p = process('./fheap')
gdb.attach(pidof('fheap'), open('debug'))
