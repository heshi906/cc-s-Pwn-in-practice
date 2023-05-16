gcc -no-pie file.c

gcc bof.c -o bof -z execstack -fno-stack-protector -g

编译时指定libc

gcc -Wl,-rpath='/home/cutecabbage/glibc-all-in-one/libs/2.23-0ubuntu3_amd64/',-dynamic-linker='/home/cutecabbage/glibc-all-in-one/libs/2.23-0ubuntu3_amd64/ld-2.23.so'  -o bi c.c



安装其他版本gcc

参考文章https://blog.csdn.net/kx453653102/article/details/107686297

http://mirror.rit.edu/gnu/gcc

```
wget http://mirror.rit.edu/gnu/gcc/gcc-4.9.4/gcc-4.9.4.tar.g
tar -axf ./gcc-4.9.4.tar.gz
cd gcc-4.9.4
sh ./contrib/download_prerequisites
```

等待

编译
```
mkdir build-gcc-4.9.4
cd build-gcc-4.9.4
../configure --prefix=/usr/local/gcc-4.9.4/ --enable-checking=release --enable-languages=c,c++ --disable-multilib
make -j4
make install
```

添加环境变量

将下面的代码添加到~/.bash_profile会使gcc默认为4.9.4
```
export PATH=/home/cc/gcc-4.9.4/bin:$PATH
```