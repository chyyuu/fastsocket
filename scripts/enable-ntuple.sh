#!/bin/sh

ethtool -K eth8 ntuple off
ethtool -K eth9 ntuple off

#ethtool -U eth9 flow-type tcp4 dst-port 0 m 0xFFF0  src-port 0 m 0x03ff action 0;
#ethtool -U eth9 flow-type tcp4 dst-port 1 m 0xFFF0  src-port 0 m 0x03ff action 1;
#ethtool -U eth9 flow-type tcp4 dst-port 2 m 0xFFF0  src-port 0 m 0x03ff action 2;
#ethtool -U eth9 flow-type tcp4 dst-port 3 m 0xFFF0  src-port 0 m 0x03ff action 3;
#ethtool -U eth9 flow-type tcp4 dst-port 4 m 0xFFF0  src-port 0 m 0x03ff action 4;
#ethtool -U eth9 flow-type tcp4 dst-port 5 m 0xFFF0  src-port 0 m 0x03ff action 5;
#ethtool -U eth9 flow-type tcp4 dst-port 6 m 0xFFF0  src-port 0 m 0x03ff action 6;
#ethtool -U eth9 flow-type tcp4 dst-port 7 m 0xFFF0  src-port 0 m 0x03ff action 7;
#ethtool -U eth9 flow-type tcp4 dst-port 8 m 0xFFF0  src-port 0 m 0x03ff action 8;
#ethtool -U eth9 flow-type tcp4 dst-port 9 m 0xFFF0  src-port 0 m 0x03ff action 9;
#ethtool -U eth9 flow-type tcp4 dst-port 10 m 0xFFF0  src-port 0 m 0x03ff action 10;
#ethtool -U eth9 flow-type tcp4 dst-port 11 m 0xFFF0  src-port 0 m 0x03ff action 11;
#
#ethtool -U eth8 flow-type tcp4 dst-port 0 m 0xFFF0  src-port 0 m 0x03ff action 0;
#ethtool -U eth8 flow-type tcp4 dst-port 1 m 0xFFF0  src-port 0 m 0x03ff action 1;
#ethtool -U eth8 flow-type tcp4 dst-port 2 m 0xFFF0  src-port 0 m 0x03ff action 2;
#ethtool -U eth8 flow-type tcp4 dst-port 3 m 0xFFF0  src-port 0 m 0x03ff action 3;
#ethtool -U eth8 flow-type tcp4 dst-port 4 m 0xFFF0  src-port 0 m 0x03ff action 4;
#ethtool -U eth8 flow-type tcp4 dst-port 5 m 0xFFF0  src-port 0 m 0x03ff action 5;
#ethtool -U eth8 flow-type tcp4 dst-port 6 m 0xFFF0  src-port 0 m 0x03ff action 6;
#ethtool -U eth8 flow-type tcp4 dst-port 7 m 0xFFF0  src-port 0 m 0x03ff action 7;
#ethtool -U eth8 flow-type tcp4 dst-port 8 m 0xFFF0  src-port 0 m 0x03ff action 8;
#ethtool -U eth8 flow-type tcp4 dst-port 9 m 0xFFF0  src-port 0 m 0x03ff action 9;
#ethtool -U eth8 flow-type tcp4 dst-port 10 m 0xFFF0  src-port 0 m 0x03ff action 10;
#ethtool -U eth8 flow-type tcp4 dst-port 11 m 0xFFF0  src-port 0 m 0x03ff action 11;
