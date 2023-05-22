#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
int main(){
    unsigned int seed;
    printf("input");
    scanf("%u",&seed);
    srand(seed);
    printf("seed input %u\n",seed);
    for(int i=0;i<114;i++){
        int r=rand()%4;
        // printf("%d",r);
        if(r==0){
            printf("c");
        }else if(r==1){
            printf("t");
        }else if(r==2){
            printf("r");
        }else{
            printf("l");
        }
    }
}