from pwn import *

name = './ch14' + ' ' + 'hello'
p = process(name)
print p.recvall()
