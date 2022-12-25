#!/usr/bin/python3.8

from ctypes import CDLL, c_char_p

import os
import sys
import time
import json

libc = CDLL('libc.so.6')
printf = libc.printf

def mivulnhub():
	for _ in range(100):
		content = input("string format vuln testing: ")
		if content == 'Exit':
			break
		if content.count('$') > 3:
			print("Limited.")
			continue
		printf(c_char_p(content.encode()))

def run():
	print("jiazhuangyoucaidan")
	print("balabalabala...")
	time.sleep(0.3)
	c = input('And, what do you want to go? ')
	if c == 'vulnhub':
		mivulnhub()
	elif c == 'other':
		print("ok~")
	else:
		pass

if __name__ == '__main__':
	run()