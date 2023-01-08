FROM ubuntu:18.04

RUN sed -i "s/http:\/\/archive.ubuntu.com/http:\/\/mirrors.tuna.tsinghua.edu.cn/g" /etc/apt/sources.list && \
    apt-get update && apt-get -y dist-upgrade && \
    apt-get update && apt-get install -y lib32z1 xinetd build-essential && \
    apt-get install -y openssl && \
    useradd -m ctf
WORKDIR /home/ctf
RUN cp -R /lib* /home/ctf && \
    cp -R /usr/lib* /home/ctf && \
    mkdir /home/ctf/dev && \
    mknod /home/ctf/dev/null c 1 3 && \
    mknod /home/ctf/dev/zero c 1 5 && \
    mknod /home/ctf/dev/random c 1 8 && \
    mknod /home/ctf/dev/urandom c 1 9 && \
    chmod 755 /home/ctf/dev/* && \
    mkdir /home/ctf/bin && \
    cp /bin/bash /home/ctf/bin && \
    cp /bin/sh /home/ctf/bin && \
    cp /bin/chmod /home/ctf/bin && \
    cp /usr/bin/timeout /home/ctf/bin && \
    cp /bin/ls /home/ctf/bin && \
    cp /bin/cat /home/ctf/bin && \
    chmod 755 /home/ctf/* && \
    chmod 755 /home/ctf/*/* && \
    rm -rf /home/ctf/lib/apt /home/ctf/lib/cpp /home/ctf/lib/gnupg /home/ctf/lib/init /home/ctf/lib/lsb /home/ctf/lib/os-release /home/ctf/lib/rsyslog /home/ctf/lib/tc /home/ctf/lib/udev /home/ctf/lib/binfmt.d /home/ctf/lib/dpkg /home/ctf/lib/gold-ld /home/ctf/lib/initramfs-tools /home/ctf/lib/ldscripts /home/ctf/lib/mime /home/ctf/lib/python2.7 /home/ctf/lib/systemd /home/ctf/lib/terminfo /home/ctf/lib/compat-ld /home/ctf/lib/gcc /home/ctf/lib/ifupdown /home/ctf/lib/insserv /home/ctf/lib/locale /home/ctf/lib/modules-load.d /home/ctf/lib/python3 /home/ctf/lib/tar /home/ctf/lib/tmpfiles.d


COPY ./ctf.xinetd /etc/xinetd.d/ctf
COPY ./pwn /home/ctf
COPY ./start.sh /
RUN chmod +x /home/ctf/* && \
    chmod +x /start.sh && \
    chown -R ctf /home/ctf && \
    chmod -R 750 /home/ctf && \
    touch /home/ctf/* && \
    touch /home/ctf/*/* && \
    echo "Blocked by ctf_xinetd" > /etc/banner_fail && \
    echo 'ctf - nproc 1500' >>/etc/security/limits.conf

CMD exec /bin/bash -c "/etc/init.d/xinetd start; trap : TERM INT; sleep infinity & wait"

EXPOSE 8888 
