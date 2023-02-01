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
functions=[]
values=[]
libcpath=''
parser = argparse.ArgumentParser(description='para transfer')
parser.add_argument('-a', action='store_true', default=False, help='show all libc')
parser.add_argument('--no', action='store_true', default=False, help='use way 2')
parser.add_argument('-f',nargs='*', default=functions, help="select function")
parser.add_argument('-l',nargs="?", type=str, default=libcpath, help='libc path')
parser.add_argument('--dump',nargs='*', default=[], help="dump function")
parser.add_argument("arg",nargs="?",type=str)
parser.add_argument("arg2",nargs="*",type=str)
args = parser.parse_args()
print(args)
libcpath=args.l
if libcpath=='' and not args.no:
    libcpath=args.arg
else :
    args.arg2.insert(0,args.arg)
libcpath=os.path.abspath(libcpath)
print('libcpath',libcpath)
functions=args.f
if functions==[]:
    functions=args.arg2
    if functions==[]:
        functions=['read','system']
print('functions',functions)

if not args.no:
    print(bcolors.WARNING+'path',libcpath,bcolors.ENDC)
    libc=ELF(libcpath)
    for i in functions:
        print(i,hex(libc.sym[i]))
    print(bcolors.OKGREEN+"LibcSearcher:",functions[0],hex(libc.sym[functions[0]]),bcolors.ENDC)
    libc2=LibcSearcher(functions[0],libc.sym[functions[0]])
    for i in range(1,len(functions)):
        print(bcolors.OKGREEN+"AddCondition:",functions[i],hex(libc.sym[functions[i]]),bcolors.ENDC)
        libc2.add_condition(functions[i],libc.sym[functions[i]])
else:
    values=functions[1::2]
    functions=functions[0::2]

    for i in range(len(functions)):
        if values[i][0:2]=='0x':
            values[i]=int(values[i],16)
        else:
            values[i]=int(values[i])
    print(bcolors.OKGREEN+"LibcSearcher:",functions[0],hex(values[0]),bcolors.ENDC)
    libc2=LibcSearcher(functions[0],values[0])
    for i in range(1,len(functions)):
        print(bcolors.OKGREEN+"AddCondition:",functions[i],hex(values[i]),bcolors.ENDC)
        libc2.add_condition(functions[i],values[i])
    
if args.a:
    print(bcolors.WARNING+"find",len(libc2.libc_list),"libc",bcolors.ENDC)
    print(libc2.libc_list)
    for i in range(len(libc2.libc_list)):
        print("["+str(i)+"] ",libc2.libc_list[i]['id'])
    if len(libc2.libc_list)==0:
        exit()
    index=input("input index: ")
    index=int(index)
    print(bcolors.WARNING+"detail",libc2.libc_list[index]['id'],bcolors.ENDC)
    print("download_url",libc2.libc_list[index]['download_url'])
    print("libs_url",libc2.libc_list[index]['libs_url'])
    print()

else:
    if len(libc2.libc_list)==0:
        print(bcolors.WARNING+'not find',bcolors.ENDC)
        exit()
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
