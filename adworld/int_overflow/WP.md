## int_overflow
checksec  
![](./pics/chc.png)  
这题逻辑相当简单初步就能判断可能出现bug的也就一个login函数和check_passwd，只是把栈溢出的位置隐藏了一下，后门函数啥的都有  
![](./pics/login.png)  
![](./pics/checkwd.png)  
bug在于check_passwd中存储字符串s长度的地方用的是unsigned int_8，能存的最大数字为255，因此在login时使s长度为259-263范围内即可