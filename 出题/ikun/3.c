#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
void fakeback(){
    puts("It's a back door, but it looks like a fake");
    system("ca t flag.txt");
}
void init()
{
    fflush(stdin);
    fflush(stdout);
    fflush(stderr);
    setvbuf(stdin,0,_IONBF,0);
    setvbuf(stdin,0,_IONBF,0);
    setvbuf(stderr,0,_IONBF,0);
    // return alarm(0x14);
}
int doit();

int main()
{
    init();
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
    char name[24]="ikunikunikunikun";
    unsigned int *seed=(unsigned int *)(name+12);

    puts("I'm an ikun, and you? You don't have to answer. I can get know it simply by your name");
    *seed= (unsigned)time(NULL);
    // *seed=1684263214;
    // printf("seed: %u",*seed);
    puts("Let's test if you are a real ikun !");
    puts("please enter your name first: ");
    for(int i=0;i<12;i++){
        name[i]=getchar();
        if(name[i]=='\n'||name[i]=='\r'){
            name[i]='\0';
            break;
        }
    }
    if(!(name[0]=='k' && name[1]=='u'&& name[2]=='n')){
        puts("It seems that you are a small black dot!");
        exit(0);
    }
    puts("I heard that a real ikun can predict all the movements of KunKun. Can you do that?");
    printf("OK, %s, Please enter the next 114 movements of KunKun (c for sign, t for jump, r for rap, l for backetball)\n",name);
    doit(*seed);

    return 0;
}

int doit(unsigned int seed){
    int wrongnum=0;
    // printf("seed input %u",seed);
    srand(seed);
    char movements[114];
    for(int i=0;i<114;i++){
        int move=rand()%4;
        if(move==0){
            movements[i]='c';
        }else if(move==1){
            movements[i]='t';
        }else if(move==2){
            movements[i]='r';
        }else{
            movements[i]='l';
        }
    }
    for(int i = 0;i<114;i++){
        printf("Turn %d \n",i+1);
        puts("Guess the movement KunKun will do:(c/t/r/l)");
        char c;
        scanf("%c",&c);
        if(c=='\n'||c=='\r'){
            i--;
            continue;
        }
        if(c!=movements[i]){
            if(wrongnum==0){
                puts("Wrong! But I will give you another chance");
                wrongnum++;
                fakeback();
            }else{
                puts("Wrong! You are not a real ikun!");
                exit(0);
            }
        }
    }
    getchar();
    puts("Congratulations on passing the test. You are a real ikun! ");
    printf("A gift for you. The puts addr is: %s\n", (char*)0x602018);
    puts("say something for our KunKun!");
    char say[0x50];
    for(int i=0;i<0x50;i++){
        say[i]=getchar();
        if(say[i]=='\n'||say[i]=='\r'){
            say[i]='\0';
            break;
        }
    }
    printf(say);
    // if(rand()%2){
        // puts("KunKun: I love you too!");
    // }else{
        puts("KunKun: I love you too!");
        system("ca t flag.txt");
    // }
    

}
