FROM ghcr.io/gztimewalker/gzctf/xinetd:alpine

COPY --chmod=755 init.sh /
COPY --chmod=755 miao /
COPY xinetd.conf /etc/xinetd.conf
COPY libc.so.6 /libc.so.6
COPY ld-2.23.so /ld-2.23.so

RUN rm /bin/cat
RUN echo echo miao~ miao~ miao~ > /bin/cat
RUN chmod +x /bin/cat

RUN rm /usr/bin/vi

CMD ["xinetd", "-dontfork"]
