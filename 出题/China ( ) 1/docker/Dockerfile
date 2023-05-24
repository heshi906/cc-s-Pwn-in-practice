FROM ghcr.io/gztimewalker/gzctf/xinetd:alpine

COPY --chmod=755 init.sh /
COPY --chmod=755 one /
COPY xinetd.conf /etc/xinetd.conf
COPY libc.so.6 /libc.so.6
COPY ld-linux-x86-64.so.2 /ld-linux-x86-64.so.2

CMD ["xinetd", "-dontfork"]
