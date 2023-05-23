#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/mman.h>
int map[0x]
void o1(char* pc){
    ++*pc;
}
void o2(char* pc){
    *pc+=8;
}
void o3(char* pc){
    *pc=getchar();
}
void o4(char* pc){
    putchar(*pc);
}
void o5(char* pc){
    free(pc);
}
void o6(char* pc){
    *pc=0;
}
int main(){
    int 
    
    return 0;
}