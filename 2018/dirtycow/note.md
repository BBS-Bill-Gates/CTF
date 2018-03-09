Linux内核的内存子系统在处理写时拷贝(Copy-To-Write)时存在条件竞争漏洞，导致可以破坏私有只读内存映射。
一个低权限的本地用户能够利用此漏洞获取其他只读内存映射的写权限，有可能进一步导致某些Linux版本提权漏洞。
低权限用户可以利用该漏洞修改只读内存，进而执行任意代码获取Root权限。
该漏洞影响所有目前运行Linux系统的设备，包含但不限于运行Linux系统的服务器，Docker容器/手机/路由器/智能设备
Linux写时拷贝技术(Copy-To-Write):
在Linux程序中, fork()会产生一个和父进程完全相同的子进程，但子进程在此后多会exec系统调用,处于效率考虑，
Linux引入"写时复制"技术，也就是只有进程空间的各段的内容要发生变化时，才会将父进程的内容复制一份给子进程。
竞态条件(Race Condition):
	它是指设备或系统出现不恰当的执行时序，而得到不正确的结果。
Linux内存管理--缺页异常处理
触发异常的线性地址处于用户空间的VMA中，但还未分配物理页，如果访问权限OK的话内核就给进程分配相应的物理页。
触发异常的线性地址不处于用户空间的VMA中，这种情况得判断是不是因为用户进程的栈空间消耗完而触发的缺页异常。
如果是的话则在用户空间对栈区域进行扩展，并且分配相应的物理页，如果不是则作为一次非法地址访问来处理，内核将终结进程。

缺页中断:
	缺页中断就是要访问的页不在主存，需要操作系统将其调入主存后在进行访问。在这个时候，被内存映射的文件实际上成了一个分页交换文件

https://dirtycow.ninja/

https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=19be0eaffa3ac7d8eb6784ad9bdbc7d67ed8e619

http://mp.weixin.qq.com/s?__biz=MzIwNDA2NDk5OQ==&mid=2651370571&idx=1&sn=68acf07ca2683a9c98fa52e900d97db3&chksm=8d39c5c3ba4e4cd58c21d0a21ca337ded2132625987e174d286f8d175034267bd09807ea9a11&scene=4#wechat_redirect
