#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/mman.h>
typedef struct Account
{
    char name[8];
    char password[28];
    unsigned int money;
    int level=0;

} Account;

int main(){
    puts("Welcome to CC's Byte, How can help you?");
    Account acc;
    while(1){
        puts("1.Create an account");
        puts("2.Deposit");
        puts("3.Withdraw");
        puts("4.Show me the money");
        puts("5.Give me the flag");
        printf("> ");
        int choice;
        scanf("%d",&choice);
        if(choice==1){
            memset(&acc,0,sizeof(acc));
            puts("What's your name?");
            read(0,acc.name,8);
            puts("What's your password?");
            read(0,acc.password,28);
            acc.money=0;
            acc.level=1;
            puts("now begin to encode your password");
            puts("......");
            for(int i=0;i<=strlen(acc.password);i++){
                acc.password[i]+=acc.password[i-1];
                acc.password[i]^=0x66;
            }
            for(int i=strlen(acc.password);i>0;i--){
                acc.password[i]^=0xcc;
                acc.password[i]-=acc.password[i-1];
            }
            puts("Done! You account has been ecrypted! Very safe! It's impossible to hack it!");
            continue;
        }
        else if(choice==4){
            printf("Your money is %d\n",acc.money);
            if(acc.money==114514){
                puts("Oh, you money is so nausea.")
                puts("[*]Event: You upgraded your account to SSSSVIP quietly while the clerk was vomiting.")

            }
        }

    }
    
    return 0;
}