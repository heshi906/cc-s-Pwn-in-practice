#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
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
void modify(){
    puts("Warning!!!  dangerous!!!  dangerous!!! You are making some changes to the program");
    puts("What address you want to modify?");
    char *addr;
    char buf[0x10];
    read(0,buf,0x10);
    sscanf(buf,"%p",&addr);
    mprotect(addr, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC);
    puts("You are a really dangerous guy, but I like it.");

}
void play(){
    puts("welcome to My game, A simple test is in front of you. ---- Get the shell with only 1 byte");
    puts("What address you want to write?");
    char *addr;
    char buf[0x10];
    read(0,buf,0x10);
    sscanf(buf,"%p",&addr);
    puts("What value you want to write?");
    int value;
    scanf("%d",&value);
    *addr=value;
    puts("Good luck!");
    memset(buf,0,0x10);
}
int main(){
    init();
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
    char temp[4];
    printf("Two gifts for you, main addr = %p and stack addr =  %p\n",&main,temp);
    play();
    modify();
    exit(0);
}