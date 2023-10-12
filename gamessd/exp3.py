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
		# gdb.attach(p,x)
		gdb.attach(proc.pidof(p)[0])
		pause()
p=process('game-amd64')
# p=remote('ctf.v50to.cc',10201)
# ru(b'name: ')
name=cyclic(23)
# name=cyclic(0x33000)
# 将内容字节码输入文件

sl(name)
ita()

	

