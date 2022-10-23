from pwn import * 
from LibcSearcher import * 
context.log_level = 'debug' 
p=process('./give_away_2')
elf=ELF('./give_away_2')
print(hex(elf.got['printf']))
print(hex(elf.plt['printf']))