#include<stdio.h> 
#include<stdlib.h> 
#include <sys/types.h>    
#include <sys/stat.h>    
#include <fcntl.h>

int main(){
    // int fd,fw;
    char buf[100]="qwweedfrgrgd";
    
    // fd = open("flag", 4);
    // read(fd,buf,120);
    FILE* fd;
    fd=fopen("./flag","r");
    fread(buf,1,120,fd);
    printf("%s%s",buf);
    close(fd);
    return 0;
}