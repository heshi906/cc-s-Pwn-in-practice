#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <seccomp.h>
#include <linux/seccomp.h>

typedef struct Myinfo {
    char secret1[50];
    char secret2[50];
    char birthday[50];
    char phone[50];
    char flag[128];
} Myinfo;
Myinfo backup;
void fakebackdoor(){
  puts("I give you system,but you can not use it!");
  system("cat flag");
}
int time=0;
int vuln(){
    char name[7];
    char flag[20];
    if(!time){
      puts("wow,welcome to your first visit,let's init!");
      Myinfo  cc_secret = {
        .secret1 = "wuwuwu ,cc don't have any money",
        .secret2= "can you v cc $50?",
        .birthday = "1919/8/10",
        .phone = "+86 114-514-1919-810",
      };
      backup=cc_secret;
    }else{
      puts("You've been here more than once, haven't you?");
      Myinfo  cc_secret = backup;
    }

    printf("I should tell you something\nfirst ,%s \nsecond ,%s ,\nthird ,cc's birthday is %s ,\nfourth ,cc' phonenum is %s,\nnow can you get my flag from these information?\n",backup.secret1,backup.secret2,backup.birthday,backup.phone);
    puts("");
    sleep(1);
    puts("Warrior, I think I need to know your name");
    fgets(name, 6, stdin);
    printf("Goodluck, ");
    printf(name);
    printf("Let's start!\n");

    printf("leave your message here:");
    fgets(flag, 114, stdin);
    strcpy(backup.flag,flag);
    time++;
    return 0;
}
void deep(){
    char buf[20]="flag_here";
    char filename[20];
    strcpy(filename,buf);
    FILE *f = fopen(filename,"r");
    if (!f) {
        printf("the file name is wrong ,feel annoying?\n");
        exit(1);
    }
    fgets(&(backup.flag), 128, f);
}
void vivo(){
  vuln();
}

int main(){
	scmp_filter_ctx ctx;
	ctx = seccomp_init(SCMP_ACT_ALLOW);
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 0);
	// seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(write), 0);
	seccomp_load(ctx);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    puts("It is a very very easy problem,only for Mion!");
    vivo();
    puts("bye bye,it seem that you can't get my flag!");
    return 0;
}

