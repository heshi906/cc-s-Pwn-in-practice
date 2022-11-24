b *address
r run
c continue
n next 不跟进
s 跟进
stack 20

vmmap



context 查看

如果有源码的话，输set context-sections code可以只显示源码

vis  查看堆


gdb at pid  --attach

start
b *$rebase(addr)

p *(struct _IO_jump_t*)_IO_list_all.vtable
p/x *_IO_list_all
