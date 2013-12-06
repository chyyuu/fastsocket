#ifndef _LINUX_FASTSOCKET_LIB_H
#define _LINUX_FASTSOCKET_LIB_H

#include <linux/ioctl.h>

typedef unsigned int u32;

#define IOC_ID 0xf5

#define FSOCKET_IOC_SOCKET _IO(IOC_ID, 0x1)
#define FSOCKET_IOC_BIND   _IO(IOC_ID, 0x2)
#define FSOCKET_IOC_LISTEN _IO(IOC_ID, 0x3)
#define FSOCKET_IOC_SETSOCKOPT _IO(IOC_ID, 0x4)
#define FSOCKET_IOC_GETSOCKOPT _IO(IOC_ID, 0x5)
#define FSOCKET_IOC_READ  _IO(IOC_ID, 0x6)
#define FSOCKET_IOC_WRITE _IO(IOC_ID, 0x7)
#define FSOCKET_IOC_ACCEPT _IO(IOC_ID, 0x8)
#define FSOCKET_IOC_SNDMSG  _IO(IOC_ID, 0x9)
#define FSOCKET_IOC_RCVMSG _IO(IOC_ID, 0x10)
#define FSOCKET_IOC_CLOSE _IO(IOC_ID, 0x11)
#define FSOCKET_IOC_RECVMSG _IO(IOC_ID, 0x12)
#define FSOCKET_IOC_EPOLL _IO(IOC_ID, 0x13)
#define FSOCKET_IOC_EPOLL_CTL _IO(IOC_ID, 0x14)
#define FSOCKET_IOC_EPOLL_WAIT _IO(IOC_ID, 0x15)
#define FSOCKET_IOC_CONNECT _IO(IOC_ID, 0x16)
#define FSOCKET_IOC_SPAWN _IO(IOC_ID, 0x17)

struct fsocket_ioctl_arg {
	u32 fd;
	u32 backlog;

	union ops_arg {
		struct socket_accept_op_t {
			void *sockaddr;
			int *sockaddr_len;
			int flags;
		}accept_op;

		struct spawn_op_t {
			int cpu;
		}spawn_op;

		struct io_op_t {
			char *buf;
			u32 buf_len;
		}io_op;

		struct socket_op_t {
			u32 family;
			u32 type;
			u32 protocol;
		}socket_op;

		struct epoll_op_t {
			u32 epoll_fd;
			u32 size;
			u32 ep_ctl_cmd;
			u32 time_out;
			struct epoll_event *ev;
		}epoll_op;
	}op;
};	

#endif
