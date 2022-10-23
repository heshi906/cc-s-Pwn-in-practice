checksec ./file  
checksec --file=./

目标：getshell
system("/bin/sh")  
system("sh")  
execve()
one_gatget

cat flag  
base64<flag  


libcbase  
获得address  
libc=LibcSearcher('fun',获得address)
libcbase=address-libc.dump('fun')  
system_addr=libcbase+libc.dump('system')  

system puts write gets read  

one_gadget ./libc.so.6
 

