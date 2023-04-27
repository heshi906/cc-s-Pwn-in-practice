from pwn import *
context.arch = 'amd64'







s='mov rsp, rdi'
print(asm(s)[::-1].hex(),s)
s='push 0x145'
print(asm(s)[::-1].hex(),s)

s='mov rsp, 0x145'
print(asm(s)[::-1].hex(),s)

s='mov rax, 0x12345678'
print(asm(s)[::-1].hex(),s)

s='mov    rax,0x0'
print(asm(s)[::-1].hex(),s)

s='div   rax'
print(asm(s)[::-1].hex(),s)

s='sub   rax,rax'
print(asm(s)[::-1].hex(),s)
