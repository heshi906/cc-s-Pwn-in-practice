# IOFILE
FILE结构在程序执行fopen等函数时会进行创建，分配在堆中，以链表的形式串联。  
但系统会在一开始自动创建三个FILE，他们是stdin、stdout、stderr，位于libc。  


_IO_FILE_plus变量指向FILE链表的头部，在没有创建其他文件结构时其指向stderr，然后依次是stdout和stdin。  
```
struct _IO_FILE_plus
{
    _IO_FILE    file;
    _IO_jump_t   *vtable;
}
```
使用p/x *_IO_list_all查看_IO_list_all
![](./pics/_IO_list_all.png)  
尝试：FILE链表为stderr->stdout->stdein，以下几种写法都能打印出stdout结构
```
p/x *(struct _IO_FILE_plus*)0x7f********** //stdout的地址
p/x *stdout

p/x *(struct _IO_FILE_plus*)_IO_2_1_stderr_.file._chain
p/x *_IO_2_1_stderr_.file._chain
```

