checksec ./file  
checksec --file=./

目标：getshell
system("/bin/sh")  
system("sh")  
execve()
one_gatget

cat flag  
base64<flag  

flag屏蔽
cat f*
cat f[l]ag

system屏蔽
'''
more:一页一页的显示档案内容
less:与 more 类似。但在用 more 时候可能不能向上翻页，不能向上搜索指定字符串，而 less 却可以自由的向上向下翻页，也可以自由的向上向下搜索指定字符串。
head:查看头几行
tac:从最后一行开始显示，可以看出 tac 是 cat 的反向显示
tail:查看尾几行
nl：命令的作用和 cat -n 类似，是将文件内容全部显示在屏幕上，并且是从第一行开始显示，同时会自动打印出行号。
od:以二进制的方式读取档案内容
vi:一种编辑器，这个也可以查看
vim:一种编辑器，这个也可以查看
sort:可以查看
uniq:可以查看
file -f:报错出具体内容。可以利用报错将文件内容带出来（-f<名称文件> 　指定名称文件，其内容有一个或多个文件名称时，让file依序辨识这些文件，格式为每列一个文件名称。）

'''

libcbase  
获得address  
libc=LibcSearcher('fun',获得address)
libcbase=address-libc.dump('fun')  
system_addr=libcbase+libc.dump('system')  

system puts write gets read  

one_gadget ./libc.so.6
 












