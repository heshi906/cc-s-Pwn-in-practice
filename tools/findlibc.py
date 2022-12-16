#!/usr/bin/python3
from pwn import *
from LibcSearcher import *
import sys
import os
import argparse
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
funtions=["read","system"]
values=[]
libcpath='./libc-2.27.so'
parser = argparse.ArgumentParser(description='para transfer')
parser.add_argument('-a', action='store_true', default=False, help='show all libc')
parser.add_argument('--no', action='store_true', default=False, help='use way 2')
parser.add_argument('-f',  nargs='*', default=funtions, help="select function")
parser.add_argument('-l', type=str, default=libcpath, help='libc path')
parser.add_argument('--dump',nargs='*', default=[], help="dump function")
parser.add_argument(' ',  nargs='*', default=sys.argv)
args = parser.parse_args()
print(args)
libcpath=args.l
if len(args.__getattribute__(' ')):
    _=args.__getattribute__(' ')
    libcpath=_[0]
    args.f=_[1::]
pwd=os.getcwd()
libcpath=os.path.abspath(libcpath)
if not args.no:
    print(bcolors.WARNING+'path',libcpath,bcolors.ENDC)
    libc=ELF(libcpath)
    for i in args.f:
        print(i,hex(libc.sym[i]))
    print(bcolors.OKGREEN+"LibcSearcher:",args.f[0],hex(libc.sym[args.f[0]]),bcolors.ENDC)
    libc2=LibcSearcher(args.f[0],libc.sym[args.f[0]])
    for i in range(1,len(args.f)):
        print(bcolors.OKGREEN+"AddCondition:",args.f[i],hex(libc.sym[args.f[i]]),bcolors.ENDC)
        libc2.add_condition(args.f[i],libc.sym[args.f[i]])
else:
    funtions=args.f[0::2]
    values=args.f[1::2]
    for i in range(len(funtions)):
        if values[i][0:2]=='0x':
            values[i]=int(values[i],16)
        else:
            values[i]=int(values[i])
        print(funtions[i],hex(values[i]))
    print(bcolors.OKGREEN+"LibcSearcher:",funtions[0],hex(values[0]),bcolors.ENDC)
    libc2=LibcSearcher(funtions[0],values[0])
    for i in range(1,len(funtions)):
        print(bcolors.OKGREEN+"AddCondition:",funtions[i],hex(values[i]),bcolors.ENDC)
        libc2.add_condition(funtions[i],values[i])
    
if args.a:
    print(bcolors.WARNING+"find",len(libc2.libc_list),"libc",bcolors.ENDC)
    for i in range(len(libc2.libc_list)):
        print("["+str(i)+"] "+libc2.libc_list[i]['id'])
    index=input("input index: ")
    index=int(index)
    print(bcolors.WARNING+"detail",libc2.libc_list[index]['id'],bcolors.ENDC)
    print("download_url",libc2.libc_list[index]['download_url'])
    print("libs_url",libc2.libc_list[index]['libs_url'])
    print()

else:
    index=0
    print(bcolors.WARNING+"find one",libc2.libc_list[0]['id'],bcolors.ENDC)
    print("download_url",libc2.libc_list[0]['download_url'])
    print("libs_url",libc2.libc_list[0]['libs_url'])
    print()

if args.dump:
    libc2.select_libc(0)
    for i in args.dump:
        if 'bin' in i:
            print("str_bin_sh",hex(libc2.dump('str_bin_sh')))
            continue
        print(i,hex(libc2.dump(i)))
