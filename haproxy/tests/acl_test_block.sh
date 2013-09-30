#!/bin/sh
#1. test append the acl 
#2. test the block_cond 


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


echo "begin test switch cond add"

echo "" >/etc/haproxy/backend.d/default_http.acl

killall haproxy
cd $CUR_PATH && ../haproxy -d -f ./acl_base.cfg &
echo "before update the acl file"
#/usr/bin/curl --connect-timeout 8 --max-time 12 -o /dev/null -s -w %{time_total}:%{size_download}:%{http_code}  
httpcode_pre=`curl --connect-timeout 8 --max-time 12 -o /dev/null -s -w %{http_code} http://localhost/`

echo "http_result: ${httpcode}"

#echo "reqrep ^([^\ ]*)\ /static/(.*)     /index.html" >/etc/haproxy/backend.d/default_http.acl
echo "after change block  rule"
echo  "acl ilogin_host hdr(host) -i sina.com\n acl ilogin_host2 hdr(host) -i localhost\nblock if ilogin_host2 \nsequence 12\n ack_url www.localhost/xyz" > /etc/haproxy/backend.d/default_http.acl


#echo "reqrep ^/static/a.html     /index.html" >/etc/haproxy/backend.d/default_http.acl

echo "after reload"

#httpcode_after=`curl --connect-timeout 8 --max-time 12  -s -w %{http_code} http://localhost/`

httpcode_after=`curl --connect-timeout 8 --max-time 12 -o /dev/null -s -w %{http_code} http://localhost/`
echo "expect httpcode_pre=200, httpcode_after=403"
echo "result http_code_pre=${httpcode_pre}, httpcode_after=${httpcode_after}"



