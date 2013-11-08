#!/bin/sh

./eth2cpu.sh -f ./cpu.conf

killall haproxy

make clean

make TARGET=linux26

./haproxy -f 1.cfg

netstat -tnpl
