#include <stdio.h>
#include <stdlib.h>
#include <string.h>


typedef struct Myinfo {
    char secret1[50];
    char secret2[50];
    char birthday[50];
    char phone[50];
    char flag[128];
} Myinfo;
Myinfo backup;
int time=0;
int vuln(){
    char name[7];
    char flag[20];
    if(!time){
      puts("wow,welcome to your first visit,let's init!");
      Myinfo cc_secret = {
        .secret1 = "wuwuwu cc don't have any money",
        .secret2= "please v cc $50",
        .birthday = "1919/8/10",
        .phone = "+86 114-514-1919-810",
      };
      backup=cc_secret;
    }else{
      puts("You've been here more than once, haven't you?");
    }

    printf("I should tell you something\nfirst ,%s \nsecond ,%s ,\nthird ,cc's birthday is %s ,\nfourth ,cc' phonenum is %s,\nnow can you get my flag from these information?",backup.secret1,backup.secret2,backup.birthday,backup.phone);
    if(time){
      puts("Warrior, I think I need to know your name");
      fgets(name, 6, stdin);
      printf("Goodluck, ");
      printf(name);
      printf("\n");
    }
    printf("leave the flag here:");
    fgets(flag, 114, stdin);
    strcpy(backup.flag,flag);
    time++;
    return 0;
}
void deep(){
    char buf[6]="gmbh\x01";
    for(int i=0;i<5;i++){
        buf[i]=buf[i]-1;
    }
    FILE *f = fopen(buf,"r");
    if (!f) {
        printf("Missing %s. Contact CC if you see this on remote.",buf);
        exit(1);
    }
    fgets(&(backup.flag), 128, f);
    puts("Oh haha,I will give you another try!");
    vuln();
}


int main(){
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    puts("It is a very very easy problem,only for Mion!");
    vuln();
    puts("bye bye,it seem that you can't get my flag!");
    return 0;
}

