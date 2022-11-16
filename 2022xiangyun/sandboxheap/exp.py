from pwn import * 
from LibcSearcher import * 
context.log_level = 'debug'
p=process('.')