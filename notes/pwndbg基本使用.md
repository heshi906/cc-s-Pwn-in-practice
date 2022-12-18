# pwndbg基本使用

| 指令 | 功能                           | 参考语法                                                     |
| ---- | ------------------------------ | ------------------------------------------------------------ |
| r    | 运行                           |                                                              |
| c    | 继续                           |                                                              |
| n/ni | 下一行（遇到函数不跟进）       |                                                              |
| s    | 下一步（遇到函数跟进）         |                                                              |
| b    | 添加断点                       | b main   /  b *0x404020                                      |
| i    | 查看                           | i r：查看所有寄存器                                          |
| x    | 查看某地址及以后的数个内存单元 | x/<n/f/u> <addr>例：x/10xg 0x404020                          |
|      |                                | n:正整数，表示需要显示的内存单元的个数                       |
|      |                                | f:表示addr指向的内存内容的输出格式，常用的有x、d、c、i等，分别代表十六进制、整数 、字符、汇编 |
|      |                                | u:每个内存单元的大小，g、w、h、b分别代表8、4、2、1字节       |
| set args     | 设置程序运行参数                               | set args -u 123458                                                             |
| watch     | 内存断点                               | watch $eax                                                             |
| context     | 打印 pwnbdg 页面信息                               |                                                              |
|dps|好看的显示内存|dps $ebp-0x10|
|disassemble|打印函数|disassemble main|


更改汇编风格为AT&T
set disassembly-flavor att

https://www.cnblogs.com/zhwer/p/12494317.html