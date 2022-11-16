### NX保护机制：
```-z execstack / -z noexecstack  # (关闭 / 开启) 堆栈不可执行```

### Canary：(关闭 / 开启 / 全开启) 栈里插入cookie信息
### 开canary好像会造成栈中局部变量的顺序有所改变
```-fno-stack-protector /-fstack-protector / -fstack-protector-all ```

### ASLR和PIE：
```-no-pie / -pie   # (关闭 / 开启) 地址随机化，另外打开后会有get_pc_thunk```

### RELRO：
```-z norelro / -z lazy / -z now   # (关闭 / 部分开启 / 完全开启) 对GOT表具有写权限```
### 去除符号表
```-s```   


### 沙盒
https://blog.csdn.net/qq_45595732/article/details/115270176
```
 sudo apt-get install libseccomp-dev
```
seccomp_init对结构体进行初始化，若参数为SCMP_ACT_ALLOW，则过滤为黑名单模式；若为SCMP_ACT_KILL，则为白名单模式，即没有匹配到规则的系统调用都会杀死进程，默认不允许所有的syscall。

seccomp_rule_add用来添加一条规则，arg_cnt为0,表示我们直接限制execve,不管参数是什么，如果arg_cnt不为0,那arg_cnt表示后面限制的参数的个数,也就是只有调用execve,且参数满足要求时,才会拦截
```
//gcc -g simple_syscall_seccomp.c -o simple_syscall_seccomp -lseccomp
#include <unistd.h>
#include <seccomp.h>
#include <linux/seccomp.h>

int main(void){
	scmp_filter_ctx ctx;
	ctx = seccomp_init(SCMP_ACT_ALLOW);
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 0);
	//seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(write), 0);
	seccomp_load(ctx);

	char * filename = "/bin/sh";
	char * argv[] = {"/bin/sh",NULL};
	char * envp[] = {NULL};
	write(1,"i will give you a shell\n",24);
	syscall(59,filename,argv,envp);//execve
	return 0;
}

```

