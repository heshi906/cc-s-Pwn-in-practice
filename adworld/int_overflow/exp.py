from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
if len(sys.argv) == 1 or sys.argv[1] == 'l':
    p = process('./int_overflow')
    elf = ELF('./int_overflow')
else:
    p = remote('61.147.171.105', 57981)
    elf = ELF('./int_overflow')
    pause()