# UAF漏洞

### 什么是UAF

在pwn中，UAF（use after free）是一种较为常见的堆漏洞，其主要产生的原因为释放堆中申请的内存后没有将指向该数据的指针清空。

用一段简单的C代码举例：

```c
#include <stdio.h>

int main(){
	char *p1;
	p1=(char*)malloc(10);
	char *p3;
	p3=(char*)malloc(10);
	memcpy(p1,"hello",10);
	printf("p1 before free addr:%p,p1:%s\n",p1,p1);
	free(p1);
	//p1=0;
	printf("p1 after free addr:%p,p1:%s\n",p1,p1);
	char *p2;
	p2=(char*)malloc(10);
	memcpy(p2,"Qba9e",10);
	printf("get p2\n");
	printf("p2 addr:%p,p2:%s\n",p2,p2);
	printf("p1 addr:%p,p1:%s\n",p1,p1);
	return 0;
}
```

输出结果：

```

```

接下来将以两道题目举例如何利用UAF

```

```



