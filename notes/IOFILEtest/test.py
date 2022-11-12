from pwn import * 
# from LibcSearcher import * 
context.log_level = 'debug' 
p=process('./binary')

gdb.attach(p)
p.interactive()