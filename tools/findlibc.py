#!/usr/bin/python3
from pwn import *
from LibcSearcher import *
import sys
import os
pwd=os.getcwd()
len=len(sys.argv)
# print('len:',len)
libcname=sys.argv[1]
if libcname[0]=='.' and libcname[1]=='/':
    libcname=libcname[2:]
if '/' in libcname:
    libc=ELF(libcname)
else:
    print(pwd+'/'+libcname)
    libc=ELF(pwd+'/'+libcname)
if len>2:
    pool=sys.argv[2:]
else:
    pool=['read','write']
print(pool)
print(pool[0],hex(libc.sym[pool[0]]))
libc2=LibcSearcher(pool[0],libc.sym[pool[0]])
for i in range(1,len-2):
    print(pool[i],hex(libc.sym[pool[i]]))
    libc2.add_condition(pool[i],libc.sym[pool[i]])
libc2.dump('system')
print("find",libc2.libc_list[0]["id"])
