#include<stdio.h>
int main(){
    int fd;
    fd=open("./text",0);
    char buf[0x100];
    for(int i=0;i<5;i++){
        buf[(int)read(fd,buf,5)]=0;
        printf("%s\n",buf);
    }
    return 0;
}