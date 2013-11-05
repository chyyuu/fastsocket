#!/bin/sh
export PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin

#default conf file
conf=/etc/eth2cpu.conf

eth2cpu_haproxy_2core=/etc/eth2cpu_haproxy_2core.conf
eth2cpu_haproxy_4core=/etc/eth2cpu_haproxy_4core.conf
eth2cpu_haproxy_6core=/etc/eth2cpu_haproxy_6core.conf
eth2cpu_lvs=/etc/eth2cpu_lvs.conf

allhaproxyconf=/etc/haproxy/haproxy*cfg
keepalivedconf1=/etc/keepalived/keepalived.conf
keepalivedconf2=/etc/keepalived/lvs.conf

#######################################################################

usage() 
{
        echo "Usage: $1 [-f file.conf ] [-h]"
	exit
}

init()
{
	#if [ ! -e $eth2cpu_haproxy_2core -o ! -e $eth2cpu_haproxy_4core -o ! -e $eth2cpu_lvs ]
	#then 
	#	echo please check eth2cpu*conf
	#	/bin/sh /sbin/sendalert $ip"need_eth2cpu*conf"
	#	exit
	#fi
	echo "in init"
}

set_eth_cpu()
{
	conf=$1
	echo $conf set_cpu

	cnt=$(wc -l $conf|awk '{print $1;}')
	for ((i=1;i<=$cnt;i++))
	do
		eth=$(awk -F'=' -v n=$i '{ if (index($0,"eth")&&NR==n) print $1;}' $conf)
		v=$(awk -F'=' -v n=$i '{ if (index($0,"eth")&&NR==n) print $2;}' $conf)
		if [ $v ]
		then
			interruptnum=$(cat /proc/interrupts | grep $eth | awk -v e=$eth '{if ($NF==e) print $0;}'| awk -F':' '{print strtonum($1);}')
			echo  $eth"="$v":"$interruptnum

			targetfile=/proc/irq/$interruptnum/smp_affinity

			[ -e $targetfile ] && echo $v > $targetfile
		fi
	done
}

########################################################################

while getopts "f:h" flag
do
        case $flag in
        f)conf=$OPTARG
        ;;
        h) 
        usage
        ;;
        *)
        usage
        ;;
	esac
done

vip=$(ip addr |grep -v "brd "| grep "inet " | grep -v "127.0.0.1" |awk '{IPSTR=IPSTR" "$2;}END{print substr(IPSTR,2);}' | awk '{for (i=1;i<=NF;i++) print $(i);}' | awk -F'/' '{print $1;}')
ip=$(ip addr | grep  "brd " | grep "inet" | awk '{print $2;}' | awk -F'/' '{ip=$1;}END{print ip;}')

init

nhaproxyconf=$(ls -l $allhaproxyconf | wc -l | awk '{print $1;}')

flag=0
if [ $nhaproxyconf -gt 0 ]
then
	#vip from haproxy

	#n=$(echo $vip | awk -v f=$allhaproxyconf '{for (i=1;i<=NF;i++) system("grep "$(i)" "f);'}|wc -l| awk '{print $1;}')
	n=1
	cntproc=$(ps aux | grep /usr/sbin/haproxy | grep $allhaproxyconf | grep -v grep | wc -l | awk '{print $1;}')
	
	if [ $n -gt 0 -a $cntproc -gt 0 ]
	then
		ncpu=$(cat /proc/cpuinfo | grep processor | wc -l)

		if [ $ncpu -eq 8 ]
		then
			set_eth_cpu $eth2cpu_haproxy_4core
		elif [ $ncpu -eq 12 ]
		then
			set_eth_cpu $eth2cpu_haproxy_6core
		elif [ $ncpu -eq 4 ]
		then
			set_eth_cpu $eth2cpu_haproxy_2core
		fi

		exit;

		flag=1
	fi
fi

#ÌØÊâ´¦Àí
tmp1=$(ip a | grep 60.28.175.115)
tmp2=$(ip a | grep 60.28.175.165)

if [ "$tmp1""x" == "x" -a "$tmp2""x" == "x" ]
then
	if [ -s $keepalivedconf1 -o -s $keepalivedconf2 ]
	then
		#vip from lvs

		[ -s $keepalivedconf1 ] && n=$(echo $vip | awk -v f=$keepalivedconf1 '{for (i=1;i<=NF;i++) system("grep "$(i)" "f);'}|wc -l| awk '{print $1;}') && cntproc=$(ps aux | grep keepalived | grep -v grep | wc -l | awk '{print $1;}') 
		[ -s $keepalivedconf2 ] && n=$(echo $vip | awk -v f=$keepalivedconf2 '{for (i=1;i<=NF;i++) system("grep "$(i)" "f);'}|wc -l| awk '{print $1;}') && cntproc=$(ps aux | grep keepalived | grep -v grep | wc -l | awk '{print $1;}')

		if [ $n -gt 0 -a $cntproc -gt 0 ]
		then
			set_eth_cpu $eth2cpu_lvs
			flag=1
		fi
	fi
fi

if [ -s $conf -a $flag -eq 0 ]
then
	set_eth_cpu $conf
fi

echo "End"

exit
