#! /bin/bash
# echo '/home/cutecabbage/glibc-all-in-one/libs/'$1
# echo '/home/cutecabbage/glibc-all-in-one/libs/'$1'ld-linux-x86-64.so.2'
ver=$2
bin=$1
patchelf --set-rpath '/home/cutecabbage/glibc-all-in-one/libs/'$ver $bin
patchelf --set-interpreter '/home/cutecabbage/glibc-all-in-one/libs/'$ver'/ld-linux-x86-64.so.2' $bin
ldd $bin
GETOPTOUT=`getopt d "$@"`  
    set -- $GETOPTOUT   
    while [ -n "$1" ]   
    do  
    case $1 in   
        -d)  
            rm -rf /usr/lib/debug
            cp -r '/home/cutecabbage/glibc-all-in-one/libs/'$ver'/.debug/' /usr/lib/debug
            ;;  
        # -b)  
        #     echo "发现 -b 选项"
        #     echo "-b 选项的参数值是：$2"
        #     shift  
        #     ;;  
        # -c)  
        #     echo "发现 -c 选项"
        #     echo "-c 选项的参数值是：$2"
        #     shift  
        #     ;;  
        # -d)  
        #     echo "发现 -d 选项"
        #     ;;  
        # --)  
        #     shift  
        #     break  
        #     ;;  
        #  *)  
        #      echo "未知选项:"$1""  
        #     ;;  
    esac  
    shift  
    done 