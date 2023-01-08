from pwn import *
p=remote('5.75.142.234',1337)
context.log_level='debug'
pause()
p.sendline('dfrgvt')
p.interactive()
p.close()