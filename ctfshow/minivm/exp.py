from pwn import *
p=process('./vm')
context.log_level=True
p.recvuntil(b'----------------HELLO WORLD----------------\n')
for i in range(1000):
    p.sendline(b'1')
    print(i)
print('finish')