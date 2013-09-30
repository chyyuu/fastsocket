#!/bin/bash

#for record the request time of every request 
#!/bin/bash 
i=0 
while [ $i -lt  100 ] 
	do 
echo -n ` date +%H:%M:%S ` 
echo -n " "
curl --connect-timeout 8 --max-time 12 -o /dev/null -s -w %{time_total}:%{size_download}:%{http_code}  http://localhost:81/index.html
echo ""
echo "same proxy: "
echo -n ` date +%H:%M:%S ` 
echo -n " "
curl --connect-timeout 8 --max-time 12 -o /dev/null -s -w %{time_total}:%{size_download}:%{http_code}  http://localhost/regular.html
echo ""
		i=`expr $i + 1` 
	done 
