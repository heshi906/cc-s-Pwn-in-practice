from pwn import *
context.log_level = 'debug'
p=process('./ikun')
gdb.attach(p)
pause()
p.recvuntil(b'please enter your name first: \n')
p.send(b'kun'*4)
p.recvuntil(b'kunkunkunkun')
seed=p.recv(4)
print("my seed",u32(seed))
moves=input("输入动作")
if moves[100]=='c':
    moves[100]='t'
else:
    moves[100]='c'
for i in range(114):
    p.sendline(moves[i])

p.recvuntil(say something for our KunKun!)

p.interactive()