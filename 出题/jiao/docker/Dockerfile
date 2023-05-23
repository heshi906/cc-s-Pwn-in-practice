FROM ghcr.io/gztimewalker/gzctf/xinetd:alpine

COPY init.sh /
RUN chmod 755 /init.sh
COPY  test /
RUN chmod 755 /test
COPY xinetd.conf /etc/xinetd.conf
COPY ld-2.23.so /ld-2.23.so
COPY libc.so.6 /libc.so.6

CMD ["xinetd", "-dontfork"]
