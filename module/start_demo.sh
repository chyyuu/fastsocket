killall server
sleep 1

rmmod fastsocket.ko 
make clean && make && insmod fastsocket.ko enable_listen_spawn=2 fsocket_debug_level=3 enable_receive_flow_deliver=1

cd ../demo
./start.sh

netstat -ntpl
