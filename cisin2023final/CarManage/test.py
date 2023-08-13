from pwn import *
p=process('./CarManager')
context.log_level='debug'
def menu(index):
    p.sendlineafter(b'>> ',index)
def userReg(name,passwd,pnum,size,data):
    p.recvuntil(b'6. Delete')
    p.sendlineafter(b'>> ',b'1')
    p.sendlineafter(b'username: ',name)
    p.sendlineafter(b'password: ',passwd)
    p.sendlineafter(b'phoneNum: ',pnum)
    p.sendlineafter(b'descript size: ',size)
    p.sendlineafter(b'descript data: ',size)
    
def userLog():
    p.recvuntil(b'6. Delete')
    p.sendlineafter(b'>> ',b'2')
def userView():
    p.recvuntil(b'6. Delete')
    p.sendlineafter(b'>> ',b'3')
def userModify():
    p.recvuntil(b'6. Delete')
    p.sendlineafter(b'>> ',b'4')
def userLogout():
    p.recvuntil(b'6. Delete')
    p.sendlineafter(b'>> ',b'5')
def userDel():
    p.recvuntil(b'6. Delete')
    p.sendlineafter(b'>> ',b'6')
