#ifndef _LINUX_FASTSOCKET_H
#define _LINUX_FASTSOCKET_H

#include <linux/ioctl.h>

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

#define ALERT 0x00
#define ERR 0x01
#define WARNING 0x02
#define INFO 0x03
#define DEBUG 0x04

extern int fsocket_get_dbg_level(void);

#define DPRINTK(level, msg, args...) ({\
	if (level < fsocket_get_dbg_level()) \
		printk(KERN_DEBUG "[CPU%d] %s:%d\t" msg, smp_processor_id(), __FUNCTION__, __LINE__, ## args); \
	})

struct fsocket_alloc {
	struct socket socket;
	struct inode vfs_inode;
	//struct dentry vfs_dentry;
};

static inline struct inode *SOCKET_INODE(struct socket *socket)
{
	return &container_of(socket, struct fsocket_alloc, socket)->vfs_inode;
}

struct read_sock_arg {
	char __user *buf;
	int size;
};

struct fsocket_ioctl_arg {
	u32 fd;
	u32 backlog;
	union ops_arg {
		struct socket_accept_op_t {
			void *sockaddr; /*user sockaddr address*/
			int *sockaddr_len; /* user sockaddr address len*/
		}accept_op;

		struct socket_bind_op_t {
			void *sockaddr;
			int sockaddr_len;
		}bind_op;

		struct socket_connect_op_t {
			void *sockaddr;
			int sockaddr_len;
		}connect_op;

		struct io_op_t {
			char *buf;
			u32 buf_len;
		}io_op;

		struct socket_op_t {
			u32 family;
			u32 type;
			u32 protocol;
		}socket_op;

		struct socket_opt_op_t {
			u32 fd;	
			u32 level;
			u32 optname;
			char * optval;
			u32 opt_len;
		}socket_opt_op;

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
