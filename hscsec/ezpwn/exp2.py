from pwn import *
import os
import sys
if len(sys.argv)==2 and sys.argv[1]=='r':
    p=remote('43.143.254.94',10881)
    libc=ELF('./libc.so.6')
else:
    p=process('./EZPWN')
    libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
elf=ELF('./EZPWN')
context.log_level='debug'
context.arch='amd64'
def dbg():
    gdb.attach(p)
    pause()
p.sendline(b'hello')
print(p.recv(6))