#include <stdio.h>
#include <stdlib.h>
#include <string.h>
long long int chunks[30];
void menu()
{

    printf("======================\n");
    printf("1.malloc        2.edit\n");
    printf("3.free          4.show one\n");
    printf("5.show all      6.exit\n");
    printf("7.edit direct   8.show direct\n");
    printf("9.add cover\n");
    printf("your choice >\n");
}
void vlun()
{
    while (1)
    {
        menu();
        int choce;
        scanf("%d", &choce);
        if (choce == 1)
        {
            int size;
            printf("size:\n");
            scanf("%d", &size);
            long long int *p = malloc(size);
            if (p == NULL)
            {
                printf("malloc failed!\n");
                continue;
            }
            int i;
            for (i = 0; i < 30; i++)
            {
                if (chunks[i] == 0)
                {
                    chunks[i] = (long long int)p;
                    printf("malloc success!\nthe index is @ %d\nthe addr is @ %p\n", i, p);
                    break;
                }
            }
        }
        else if (choce == 2)
        {
            int index;
            printf("index:\n");
            scanf("%d", &index);
            if (index < 0 || index >= 30)
            {
                printf("index error!\n");
                continue;
            }
            if (chunks[index] == 0)
            {
                printf("this chunk is free!\n");
                continue;
            }
            printf("thing:\n");
            read(0, (void *)chunks[index], 0x100);
        }
        else if (choce == 3)
        {
            int index;
            printf("index:\n");
            scanf("%d", &index);
            if (index < 0 || index >= 30)
            {
                printf("index error!\n");
                continue;
            }
            if (chunks[index] == 0)
            {
                printf("this chunk is free!\n");
                continue;
            }
            free((void *)chunks[index]);
        }
        else if (choce == 4)
        {
            int index;
            printf("index:\n");
            scanf("%d", &index);
            if (index < 0 || index >= 30)
            {
                printf("index error!\n");
                continue;
            }
            if (chunks[index] == 0)
            {
                printf("this chunk is free!\n");
                continue;
            }
            printf("things:%s!!!\n", (char *)chunks[index]);
        }
        else if (choce == 5)
        {
            printf("chunks\n");
            int i;
            for (i = 0; i < 30; i++)
            {
                if (chunks[i] != 0)
                {
                    if (i % 2 == 0)
                        printf("%d: %p %#x,  ", i, chunks[i], *(int *)(chunks[i] - 8));
                    if (i % 2 == 1)
                        printf("%d: %p %#x,\n", i, chunks[i], *(int *)(chunks[i] - 8));
                }
            }
            puts("finish");
        }
        else if (choce == 6)
        {
            exit(0);
        }
        else if (choce == 7)
        {
            long long int addr;
            printf("position:\n");
            scanf("%lld", &addr);
            read(0, (void *)addr, 0x100);
        }
        else if (choce == 8)
        {
            long long int addr;
            printf("position:\n");
            scanf("%lld", &addr);
            int len;
            printf("len:\n");
            scanf("%d", &len);
            write(1, (void *)addr, len);
        }
        else if (choce == 9)
        {
            int index;
            printf("index:\n");
            scanf("%d", &index);
            int size;
            printf("size:\n");
            scanf("%d", &size);
            long long int *p = malloc(size);
            if (p == NULL)
            {
                printf("malloc failed!\n");
                continue;
            }
            chunks[index] = (long long int)p;
            printf("malloc success!\nthe index is @ %d\nthe addr is @ %p\n", index, p);
            break;
        }

        else
        {
            printf("error choice!\n");
        }
    }
}
int main()
{
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    printf("Welcome to my test!\n");
    long long int puts_addr = (long long int)puts;
    printf("the puts addr is @ %lld\n", puts_addr);
    vlun();
    return 0;
}