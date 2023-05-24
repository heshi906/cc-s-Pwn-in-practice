#!/bin/sh
# Add your startup script
echo $GZCTF_FLAG > /home/ctf/flag
# chmod 777 /home/ctf/flag
# export GZCTF_FLAG=""
# DO NOT DELETE
/etc/init.d/xinetd start;
sleep infinity;
