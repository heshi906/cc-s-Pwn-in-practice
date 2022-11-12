# leak  
首先需要注意此题libc版本为2.27 1.6，此版本的tcache中会有双指针，而如果是2.27 1.4则没有双指针。 
查看stdout   
``` 
p/x *stdout
```
