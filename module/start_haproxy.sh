killall haproxy
sleep 1

rmmod fastsocket.ko 
make clean && make && insmod fastsocket.ko enable_listen_spawn=2 fsocket_debug_level=4 enable_receive_flow_deliver=1

cd ../haproxy
./start.sh

#netstat -ntpl
