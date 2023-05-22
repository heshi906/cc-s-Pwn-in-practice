#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
int init()
{
    fflush(stdin);
    fflush(stdout);
    fflush(stderr);
    setvbuf(stdin,0,_IONBF,0);
    setvbuf(stdin,0,_IONBF,0);
    setvbuf(stderr,0,_IONBF,0);
}
char burn[] = "你出生了，为你自己取一个霸气的名字吧！";
char *life[][50] = {
    {
        "你家很有钱，爸爸告诉你将来不用努力了",
        "5岁那年你发现你爸是骗你的，家里还欠了一百万"
    },{
        "你出生在一个普通家庭",
        "父母告诉你要好好读书"
    },{
        "你出生在一间厕所里，不知道妈妈是谁，开始大哭",
        "你被清洁工发现并带回去收养"
    }
};
char *study[] = {
        "你很努力，苦读十年",
        "你天天打游戏，啥都没学，终于迎来了高考"
    };
char *collage[] = {
        "你终于考上了双非",
        "你考上了一所普通一本",
        "你最终考上了西北工业大学"
    };

char *work[] = {
    "你完全不学习，毕业后去做了清洁工",
    "你对黑客技术感兴趣，学习安全知识，毕业后参与面试，成为一名安全工程师",
    "你对黑客技术感兴趣，学习安全知识，毕业后没找到工作去做了清洁工",
    "你对黑客技术感兴趣，学习安全知识，一次偶然的机会，你发现了一家公司的漏洞，得到了公司的offer",
    "你对黑客技术感兴趣，学习安全知识，一次渗透时忘记擦除痕迹，被条子抓走了",
};
int moneylist[]={1,3,5};
int moneyindex;
void initmoney(){
   // remove("/tmp/money.txt");
    puts("init");
    //FILE *f;
    //f = fopen("/tmp/money.txt", "r");
    //char buffer[255];
    //fscanf(f, "%s", buffer);
    //printf("%s",buffer);
    FILE *fp;
    fp = fopen("/tmp/money.txt", "w");
    if (fp == NULL) {
    printf("文件创建失败");
    exit(1);
    }
    fprintf(fp, "%d", 0);
    fclose(fp);
}
int get_money(){
    FILE *fp;
    char buffer[255];

    // 打开money.txt文件
    fp = fopen("/tmp/money.txt", "r");
    if (fp == NULL) {
        printf("文件打开失败");
        exit(1);
    }

    // 读取文件中的数字
    fscanf(fp, "%s", buffer);
    int money = atoi(buffer);
    return money;
}
int add_money(int num){
    int money=get_money();
    int newmoney=money+num;
    FILE *fp;
    fp = fopen("/tmp/money.txt", "w");
    if (fp == NULL) {
        printf("文件打开失败");
        exit(1);
    }
    fprintf(fp, "%d", newmoney);
    fclose(fp);
    return newmoney;
}
void shell(){
    system("/bin/sh");
}
void beginwork(){
    int money=get_money();
    printf("当前资金：%d万 你这个月的选择是？0.摆烂 1.继续工作 2.疯狂加班 3.创业 4.hint\n",money);
    int i;
    printf("> ");
    scanf("%d", &i);
    if(i==0){
        puts("你摆烂了一个月，老板把你开除了");
        exit(0);
        return;
    }
    else if(i==1){
        if(rand()%15==0){
            puts("你过劳猝死了，你的钱再也没机会用了QAQ");
            exit(0);
        }
        printf("你工作了一个月，老板给你发了%d万，你离创业又近了一步\n",moneylist[moneyindex]);
        money=add_money(moneylist[moneyindex]);
    }
    else if(i==2){
        if(rand()%7==0){
            puts("你过劳猝死了，你的钱再也没机会用了QAQ");
            exit(0);
        }
        printf("你努力加班了一个月，老板很开心，给你发了%d万，你离创业又近了一步\n",moneylist[moneyindex]*2);
        money=add_money(moneylist[moneyindex]*2);
    }
    else if(i==3){
        if(money<200){
            puts("你创业失败了，亏损100万，可能是钱没准备够，下次重开再试试吧~");
            exit(0);
        }
        puts("你决定创业，这次你成功了！");
        shell();
        return;
    }
    else{
        puts("hint:实在是攒不够钱，交给你了！另一个我！");
    }
}
int main()
{
    init();
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
    initmoney();
    puts("欢迎来到人生重开模拟器之我要创业赚大钱，按下回车键开始吧~");
    puts("<Press enter to continue.>");
    getchar();
    unsigned long n;
    srand((unsigned)time(NULL));
    puts(burn);
    printf("> ");
    char name[20];
    scanf("%s", name);
    printf("你好,%s,你的人生开始了\n",name);
    int lifeindex=rand()%3;
    puts(life[lifeindex][0]);
    puts("<Press enter to continue.>");
    getchar();
    getchar();
    puts(life[lifeindex][1]);
    puts("<Press enter to continue.>");
    getchar();
    puts(study[rand()%2]);
    puts("<Press enter to continue.>");
    getchar();
    puts("你想长大后创业赚大钱");
    puts("<Press enter to continue.>");
    getchar();
    puts(collage[rand()%3]);
    puts("<Press enter to continue.>");
    getchar();
    int worknum=rand()%5;
    puts(work[worknum]);
    puts("<Press enter to continue.>");
    getchar();
    if(worknum==4){
        puts("你的人生已经没有希望了，重开吧");
        return 0;
    }
    if(lifeindex==0){
        puts("你家欠债累累,你的原始资金是-100万");
        add_money(-100);
    }else if(lifeindex==1){
        puts("你的原始资金是10万");
        add_money(10);
    }else{
        puts("你中了彩票，你的原始资金是20万");
        add_money(20);
    }
    puts("<Press enter to continue.>");
    getchar();

    moneyindex=rand()%3;
    printf("终于要开始工作了，老板给你开的钱是一个月%d万，开始攒钱吧，记住你的目标是最终创业！\n",moneylist[moneyindex]);

    for(int i=0;i<5;i++){
        beginwork();
    }
    puts("你过劳猝死了，你的钱再也没机会用了QAQ");
    exit(0);
}
