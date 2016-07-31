#!/bin/bash -e

sudo debootstrap --arch i386 hardy ./hardy-chroot http://old-releases.ubuntu.com/ubuntu
sudo docker build -t w4sp/labs:sploitable .

