from pwn import *
p=process(argv=['./bufbomb', '-u','22'])
gdb.attach(p,'b read')
p.interactive()