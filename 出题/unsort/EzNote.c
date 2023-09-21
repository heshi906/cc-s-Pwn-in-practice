#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void read_input(char *buf, size_t size) {
  int ret;
  ret = read(0, buf, size);
  if (ret <= 0) {
    puts("Error");
    _exit(-1);
  }
}
char *nothing[4];
char *heaparray[4];

void menu() {
  puts("--------------------------------");
  puts("           Ez Note              ");
  puts("--------------------------------");
  puts(" 1. Create a Note               ");
  puts(" 2. Edit a Note                 ");
  puts(" 3. Show a Note                 ");
  puts(" 4. Delete a Note               ");
  puts(" 5. Exit                        ");
  puts("--------------------------------");
  printf("Your choice :");
}
void create_heap() {
  int i;
  char buf[8];
  size_t size = 0;
  int flag=0;
  for (i = 0; i < 4; i++) {
    if (!heaparray[i]) {
      flag=1;
      printf("Length of Note : ");
      read(0, buf, 8);
      size = atoi(buf);
      if(size>0x100){
        puts("Too Large");
        exit(1);
      }
      heaparray[i] = (char *)malloc(size);
      if (!heaparray[i]) {
        puts("Allocate Error");
        exit(2);
      }
      printf("Content of Note:");
      read_input(heaparray[i], size);
      puts("SuccessFul");
      break;
    }
  }
  if(!flag){
    puts("Full");
    _exit(0);
  }
}

void edit_heap() {
  int idx;
  char buf[8];
  size_t size;
  printf("Index :");
  read(0, buf, 4);
  idx = atoi(buf);
  if (idx < 0 || idx >= 4) {
    puts("Out of bound!");
    _exit(0);
  }
  if (heaparray[idx]) {
    printf("Length of Note : ");
    read(0, buf, 8);
    size = atoi(buf);
    printf("Content of Note : ");
    read_input(heaparray[idx], size);
    puts("Done !");
  } else {
    puts("No such Note !");
  }
}
void show_heap(){
  int idx;
  char buf[8];
  size_t size;
  printf("Index :");
  read(0, buf, 4);
  idx = atoi(buf);
  if (idx < 0 || idx >= 4) {
    puts("Out of bound!");
    _exit(0);
  }
  if (heaparray[idx]) {
    printf("content: ");
    puts(heaparray[idx]);
  } else {
    puts("No such Note !");
  }
}

void delete_heap() {
    puts("No delete for you");
}

void back() { system("cat ./flag"); }

int main() {
  char buf[8];
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 2, 0);
  nothing[0] = (char *)malloc(0xf20);
  printf("A gift for you~: %p\n",nothing);
  while(1) {
    menu();
    read(0, buf, 8);
    switch (atoi(buf)) {
    case 1:
      create_heap();
      break;
    case 2:
      edit_heap();
      break;
    case 3:
      show_heap();
      break;
    case 4:
      delete_heap();
      break;
    case 5:
      exit(0);
      break;
    default:
      puts("Invalid Choice");
      break;
    }
  }
  puts("Good Luck next time");
  return 0;
}
