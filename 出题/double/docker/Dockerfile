FROM ghcr.io/gztimewalker/gzctf/xinetd:alpine

COPY --chmod=755 init.sh /
COPY --chmod=755 double /
COPY xinetd.conf /etc/xinetd.conf
COPY ld-2.23.so /ld-2.23.so
COPY libc.so.6 /libc.so.6

CMD ["xinetd", "-dontfork"]
