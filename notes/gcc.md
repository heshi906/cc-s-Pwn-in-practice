gcc -no-pie file.c

gcc bof.c -o bof -z execstack -fno-stack-protector -g