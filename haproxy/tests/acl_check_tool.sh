#!/bin/sh

if [ $# != 1 ] 
	then

		echo " Usage $0 filename"
		exit -1
fi

if [ ! -e $1 ] 
	then 
		echo "ERROR:acl file not exit"
		exit -1
fi

if [ ! -d /etc/haproxy/backend.d/ ]
	then
		mkdir -p /etc/haproxy/backend.d/

fi

if [ ! -d /etc/haproxy/backend.d/ ]
	then 
		echo "ERROR: Can't create or access dir /etc/haproxy/backend.d/ please use root privildge"
		exit -1
fi

#cp  -r $1  /etc/haproxy/backend.d/
if [ ! -e "/etc/haproxy/backend.d/$1" ]
	then 
	"ERROR: Can't access /etc/haproxy/backend.d/, please update your privilidge"
	exit -1
fi 
./acl_file_verify $1


