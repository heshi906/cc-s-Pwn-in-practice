from pwn import *
from LibcSearcher import *
lib=ELF('./libc.so.6')
read_addr=lib.symbols['read']
write_addr=lib.symbols['write']
print(read_addr)
print(write_addr)
libc=LibcSearcher('read',read_addr)
libc.add_condition('write',write_addr)
print(libc)
# print(libc.search('system'))