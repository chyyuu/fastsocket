#!/bin/bash

# update the acl file many times 
# expect result: regular's function return 200
# expect 
CUR_PATH=`pwd`
NGINX_PATH0=/home/xilei/bin/nginx
NGINX_PATH1=/home/xilei/bin/nginx1
NGINX_PATH2=/home/xilei/bin/nginx2
NGINX_PATH3=/home/xilei/bin/nginx3
NGINX_PATH4=/home/xilei/bin/nginx4
NGINX_PATH5=/home/xilei/bin/nginx5
NGINX_PATH6=/home/xilei/bin/nginx6
NGINX_PATH7=/home/xilei/bin/nginx7
NGINX_PATH8=/home/xilei/bin/nginx8
NGINX_PATH9=/home/xilei/bin/nginx9

killall nginx
cd $NGINX_PATH0 && ./sbin/nginx
cd $NGINX_PATH1 && ./sbin/nginx
cd $NGINX_PATH2 && ./sbin/nginx
cd $NGINX_PATH3 && ./sbin/nginx
cd $NGINX_PATH4 && ./sbin/nginx
cd $NGINX_PATH5 && ./sbin/nginx
cd $NGINX_PATH6 && ./sbin/nginx
cd $NGINX_PATH7 && ./sbin/nginx
cd $NGINX_PATH8 && ./sbin/nginx
cd $NGINX_PATH9 && ./sbin/nginx

echo "before reload acl\n" >>$CUR_PATH/regular_result
echo "" >/etc/haproxy/backend.d/default_http.acl

killall haproxy
if [ -e ../hapoxy ] 
	then
	echo "the haproxy bin file is not exist, please compile it"
	exit
fi
cd $CUR_PATH && ../haproxy -d -f ./acl_base.cfg >./haproxy.re 2>./ha.err &

echo "before update the acl file"
cd $CUR_PATH && ./acl_regular.sh >./regular_result & 


echo "http_result: ${httpcode}"

i=0
while [ $i -lt  1000 ] 
	do 
	echo `date +%H:%M:%S`
	cd $CUR_PATH && echo "before reload acl\n" >>regular_result
	#echo " reqrep ^([^\ ]*)/static/(.*)     \1/\2"  >/etc/haproxy/backend.d/default_http.acl

#echo "reqrep ^/static/a.html     /index.html" >/etc/haproxy/backend.d/default_http.acl

	sleep 1
	#cat acl_7lay.conf >/etc/haproxy/backend.d/default_http.acl

	echo "after reload"
	cd $CUR_PATH && echo "after reload acl\n" >>regular_result

	i=`expr $i + 1` 
done

httpcode=`curl --connect-timeout 8 --max-time 12 -o /dev/null -s -w %{http_code} http://localhost/static/a.html`

echo `date +%H:%M:%S`
echo "http_result: ${httpcode}"
