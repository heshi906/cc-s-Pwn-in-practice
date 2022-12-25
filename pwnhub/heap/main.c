// ubuntu 22.04 + musl1.2.3
// http://git.musl-libc.org/cgit/musl/
// musl-gcc main.c -o pwn
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char* ptr[0x10] = {};

int read_int(){
    char buf[0x10] = ""; 
    read(0, buf, 0x8);
    return atoi(buf);
}

int main(){
    int n = 0;
    unsigned int id = 0, size = 0;
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    puts("Welcome PwnHub2022.");
loop:
    printf(
     "1. add 2. edit\n"
     "3. del 4. show\n"
     "0. exit\n"
     "> ");
    n = read_int();
    if(n > 4){
        goto loop;
    }
    if(n == 0){
        puts("bye~");
        exit(0);
    }
    printf("Which one?\n> ");
    id = read_int();
    if ( n < 3 ){
        printf("Size: ");
        size = read_int();
        ptr[id] = n == 1 ? malloc(size) : ptr[id]; 
        printf("Content: ");
        read(0, ptr[id], size);
    } else {
        n == 3 ? free(ptr[id]) : puts(ptr[id]);
    }
    puts("Done.");
    goto loop;

    return 0;
}
