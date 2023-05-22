FROM ghcr.io/gztimewalker/gzctf/xinetd:alpine

COPY --chmod=755 init.sh /
COPY --chmod=755 life /
COPY xinetd.conf /etc/xinetd.conf
COPY libc.so.6 /libc.so.6
COPY ld-2.23.so /ld-2.23.so

CMD ["xinetd", "-dontfork"]
