#这题要改变scanf内部结构，目前看不懂https://blog.csdn.net/seaaseesa/article/details/103114909
from pwn import *
from LibcSearcher import *
p=process('./echo_back')
elf=ELF('./echo_back')
context.log_level='debug'

def setname(name):
    p.sendlineafter(b'choice>> ',b'1')
    p.sendafter(b'name:',name)
def echo(length,content):
    p.sendlineafter(b'choice>> ',b'2')
    p.sendlineafter(b'length:',str(length).encode())
    p.send(content)
def exit():
    p.sendlineafter(b'choice>> ',b'3')
setname(b'aaaa')
pause()
echo(2147483647,b'b'*9)
p.interactive()