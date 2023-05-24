#!/bin/sh
# Add your startup script
# Change $GZCTF_FLAG to your flag

echo $GZCTF_FLAG > /home/ctf/flag

# DO NOT DELETE
/etc/init.d/xinetd start;
sleep infinity;
