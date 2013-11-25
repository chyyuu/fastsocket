#!/bin/sh

./eth2cpu.sh -f ./cpu.conf

killall haproxy

sleep 1

make clean; make TARGET=linux26

LD_PRELOAD=../library/libsocket.so ./haproxy -f 1.cfg

netstat -tnpl
