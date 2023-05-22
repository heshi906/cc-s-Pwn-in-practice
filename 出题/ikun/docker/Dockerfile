FROM ghcr.io/gztimewalker/gzctf/xinetd:alpine

COPY --chmod=755 init.sh /
COPY --chmod=755 ikun /
COPY xinetd.conf /etc/xinetd.conf
COPY libc-2.27.so /libc-2.27.so
COPY ld-linux-x86-64.so.2 /ld-linux-x86-64.so.2

CMD ["xinetd", "-dontfork"]
