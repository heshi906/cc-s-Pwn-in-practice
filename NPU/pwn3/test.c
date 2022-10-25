#include<stdio.h> 
#include<stdlib.h> 


int main(){
    FILE *fp;
    char buf[100];
    fp = fopen("flag", "r");
    fgets(buf, 100, fp);
    printf("%s",buf);
    return 0;
}