#!/bin/bash


sleep $(shuf -i 10-20 -n 1) && dhclient
#start vsftpd
/etc/init.d/xinetd start
#start samba
/etc/init.d/samba start
#start rmiregistry -- this should just hang
/usr/bin/rmiregistry
