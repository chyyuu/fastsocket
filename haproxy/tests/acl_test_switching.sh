#!/bin/sh
#switch access one host, after switch access another host ,need human review

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
httpcode_pre=`curl --connect-timeout 8 --max-time 12  -s -w %{http_code} http://localhost/`

echo "http_result: ${httpcode}"

#echo "reqrep ^([^\ ]*)\ /static/(.*)     /index.html" >/etc/haproxy/backend.d/default_http.acl

echo "after change switching_rule  localhost"
echo "acl ilogin_host hdr(host) -i sina.com\n acl ilogin_host2 hdr(host) -i localhost\nuse_backend  backend2 if ilogin_host2" > /etc/haproxy/backend.d/default_http.acl


#echo "reqrep ^/static/a.html     /index.html" >/etc/haproxy/backend.d/default_http.acl

echo "after reload"

httpcode_after=`curl --connect-timeout 8 --max-time 12  -s -w %{http_code} http://localhost/`

echo "expect:httpcode_pre=400, httpcode_after=200 "
echo "result:httpcode_pre=${httpcode_pre}, httpcode_after=${httpcode_after}"
echo "http_result: ${httpcode}"


