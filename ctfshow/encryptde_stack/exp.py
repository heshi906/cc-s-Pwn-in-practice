from pwn import *
from LibcSearcher import *
p=process('./encrypted_stack')
elf=ELF('./encrypted_stack')
context.log_level='debug'
