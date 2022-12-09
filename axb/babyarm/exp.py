from pwn import *
context.log_level = 'debug'
io = process(["./qemu-arm-static", "-L", "./", "./chall"])
gdb.attach(io)
io.interactive()