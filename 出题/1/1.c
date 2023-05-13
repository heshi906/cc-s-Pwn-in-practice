#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int init()
{
    fflush(stdin);
    fflush(stdout);
    fflush(stderr);
    setvbuf(stdin,0,_IONBF,0);
    setvbuf(stdin,0,_IONBF,0);
    setvbuf(stderr,0,_IONBF,0);
    return alarm(0x14);
}

int main()
{
    init();
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
    puts("My cat is very cute! I want to show it to you!");
    printf("< Go and see ? >(y/n)");
    char c;
    scanf("%c", &c);
    if (c == 'y')
    {
        puts("OK,go with me!");
        // 延时1秒
        sleep(1);
        printf("...");
        sleep(1);
        printf("...");
        sleep(1);
        puts("...");
        puts("Oh Shit, my cat is gone!");
        puts("But I want to give you the shell, go and find the flag!");
        system("/bin/sh");
    }
    else
    {
        printf("OK, I will show it to you next time!");
        return 0;
    }
    return 0;
}
