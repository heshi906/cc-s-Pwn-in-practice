#include <stdio.h>
#include <stdlib.h>
#include<string.h>
int main()
{
  char a[100];
  char str[100];
  char st[100]="afgkiuiuligujsliuhdtiulhgtuihtuihouikefgkygk";
  printf("Please login:\n");
  scanf("%s",a);
  printf(a);
  printf("Password:");
  scanf("%s",str);
  if ( !strncmp(str, st, 0x32) )
  {
    printf("Welcome, my admin.");
    system("cat flag");
  }
  else
  {
    printf("Password Wrong");
  }
  return 0;
}