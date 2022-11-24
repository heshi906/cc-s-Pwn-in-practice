gcc -no-pie file.c

gcc bof.c -o bof -z execstack -fno-stack-protector -g

编译时指定libc

gcc -Wl,-rpath='/home/cutecabbage/glibc-all-in-one/libs/2.23-0ubuntu3_amd64/',-dynamic-linker='/home/cutecabbage/glibc-all-in-one/libs/2.23-0ubuntu3_amd64/ld-2.23.so'  -o bi c.c
