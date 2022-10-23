from pwn import *
context.log_level = 'debug'

if len(sys.argv) == 1 or sys.argv[1] == 'l':
    p = process('./pwn')
    elf = ELF('./pwn')
else:
    p = remote('61.147.171.105', 52678)
    elf = ELF('./pwn') 
    pause()