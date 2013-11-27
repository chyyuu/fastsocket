#!/bin/sh

killall nginx

usleep 1

LD_PRELOAD=../library/libsocket.so ./objs/nginx -c `pwd`/conf/nginx.conf

sleep 2

killall nginx
