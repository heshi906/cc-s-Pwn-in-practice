#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
void init()
{
    fflush(stdin);
    fflush(stdout);
    fflush(stderr);
    setvbuf(stdin,0,_IONBF,0);
    setvbuf(stdin,0,_IONBF,0);
    setvbuf(stderr,0,_IONBF,0);
    return alarm(0x14);
}
int main() {
    init();
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
    char str[100];
    unsigned int num;

    printf("请输入一个数字，它比某个很臭的数字大，你知道应该输入什么");
    scanf("%s", str);

    if (strlen(str) > 4) {
        printf("我已经没耐心听下去了\n");
        return 0;
    }

    num = atoi(str);

    if (num > 114514) {
        printf("成功\n");
        system("/bin/sh");
    } else {
        printf("滚\n");
    }

    return 0;
}
