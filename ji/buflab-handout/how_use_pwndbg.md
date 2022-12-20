# pwndbg基本使用

开启调试：gdb proname（安装完成后使用gdb命令打开的自动是pwndbg，如果想关掉的话把文件~/.gdbinit注释掉就行了）
<table>
  <tr>
    <td>指令</td>
    <td>功能</td>
    <td>参考语法</td>
  </tr>
  <tr>
    <td>r（run）</td>
    <td>运行</td>
    <td></td>
  </tr>
  <tr>
    <td>c（continue）</td>
    <td>继续</td>
    <td></td>
  </tr>
    <tr>
    <td>n/ni（next）</td>
    <td>下一行（遇到函数不跟进）</td>
    <td>ni是在汇编层面的下一行；n是在c语言层面的下一行，即可能一次跳过多行汇编（在程序能找到c源码时才会这样）</td>
  </tr>
    <tr>
    <td>s（step）</td>
    <td>下一步（遇到函数跟进）</td>
    <td></td>
  </tr>
    <tr>
    <td>b（break）</td>
    <td>	添加断点</td>
    <td>b main / b *0x404020</td>
  </tr>
<tr>
    <td>i（info）</td>
    <td>	查看</td>
    <td>i r：查看所有寄存器</td>
  </tr>
      <tr>
    <td rowspan="4">x</td>
    <td rowspan="4">	查看某地址及以后的数个内存单元</td>
    <td>x/&ltn/f/u&gt 例：x/10xg 0x404020</td>
  </tr>
  <tr>
    <td>n:正整数，表示需要显示的内存单元的个数</td>
  </tr>
  <tr>
    <td>f:表示addr指向的内存内容的输出格式，常用的有x、d、c、i等，分别代表十六进制、整数 、字符、汇编</td>
  </tr>
  <tr>
    <td>u:每个内存单元的大小，g、w、h、b分别代表8、4、2、1字节</td>
  </tr>
  <tr>
    <td>set args</td>
    <td>设置程序运行参数</td>
    <td>set args -u 123458</td>
  </tr>
    <tr>
    <td>watch</td>
    <td>内存断点</td>
    <td>watch $eax</td>
  </tr>
    <tr>
    <td>context</td>
    <td>打印 pwnbdg 页面信息</td>
    <td></td>
  </tr>
    <tr>
    <td>dps</td>
    <td>好看的显示内存</td>
    <td>dps $ebp-0x10</td>
  </tr>
    <tr>
    <td>disassemble</td>
    <td>打印函数</td>
    <td>disassemble main</td>
  </tr>
</table>

设置初始参数与使用文件内容输入，在进入pwndbg后
```
set args -u 114514 < txt.txt
```

更改汇编风格为AT&T
```
set disassembly-flavor att
```
更多用法参考网站
https://www.cnblogs.com/zhwer/p/12494317.html
或者输入help all得到所有可选命令

# objdump

objdump -d -M intel ./bufbomb > bomb.asm #intel
objdump -d  ./bufbomb > bomb.asm   #at&t

