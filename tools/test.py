#!/usr/bin/python3
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-a",nargs=1,type=str, default=[])
parser.add_argument("-b",nargs=1,type=str, default=[])
parser.add_argument("arg",nargs="?",type=str)
parser.add_argument("arg2",nargs="*",type=str)


args = parser.parse_args()
print(args)
print(args.arg)  # 输出 arg1
print(args.arg2)  # 输出 arg1
