from pwn import *
p=process("./prob22-crackme")
gdb.attach(p)
p.interactive()
