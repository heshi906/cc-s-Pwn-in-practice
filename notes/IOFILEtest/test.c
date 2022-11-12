#include<stdio.h>
#include<stdlib.h>
#include <string.h>
#define system_ptr 0x7ffff7a52390;

int main(void)
{
    FILE *fp;
    long long *vtable_ptr;
    char str[20]="flag{1234567890}";
    fp=fopen("123.txt","rw");
    vtable_ptr=*(long long*)((long long)fp+0xd8);     //get vtable
    printf("input:");
    getchar();

    printf("%x\n",fp);
    printf("%x\n",vtable_ptr);

    // vtable_ptr[7]=system_ptr //xsputn


    fwrite("hi",2,1,fp);
}