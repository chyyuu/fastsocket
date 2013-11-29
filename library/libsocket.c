#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <linux/eventpoll.h>

#define __USE_GNU
#include <sched.h>
#include <dlfcn.h>

#include "libsocket.h"

static int fsocket_channel_fd = -1;

#define SYSCALL_DEFINE(name, ...) __wrap_##name(__VA_ARGS__)
#define SYSCALL(name, ...)  __real_##name(__VA_ARGS__)


#define FSOCKET_DBG(level, msg, ...) \
do {\
	fprintf(stderr, "FATSOCKET LIBRARY:" msg, ##__VA_ARGS__);\
}while(0)

#define MAX_LISTEN_FD	65536

//TODO: Need Lock for Multi-thread programme

static int fsocket_listen_fds[MAX_LISTEN_FD];

inline int get_cpus()
{
        return sysconf(_SC_NPROCESSORS_ONLN);
}

__attribute__((constructor))
void fastsocket_init(void)
{
	int ret = 0;
	int i;
	cpu_set_t cmask;

	ret = open("/dev/fastsocket_channel", O_RDONLY);
	if (ret < 0) {
		FSOCKET_DBG(FSOCKET_ERR, "Open fastsocket channel failed, please CHECK\n");
		exit(-1);
	}
	fsocket_channel_fd = ret;

	for (i = 0; i < MAX_LISTEN_FD; i++)
		fsocket_listen_fds[i] = 0;

        CPU_ZERO(&cmask);

	for (i = 0; i < get_cpus(); i++)
		CPU_SET(i, &cmask);

        ret = sched_setaffinity(0, get_cpus(), &cmask);
	if (ret < 0) {
		FSOCKET_DBG(FSOCKET_ERR, "Clear process CPU affinity failed\n");
		exit(-1);
	}

	return;
}

__attribute__((destructor))
void fastsocket_uninit(void)
{
	close(fsocket_channel_fd);

	return;
}

int socket(int family, int type, int protocol)
{
	static int (*real_socket)(int, int, int) = NULL;
	int fd = -1;
	struct fsocket_ioctl_arg arg;

	if (fsocket_channel_fd != 0) {
		arg.op.socket_op.family = family;
		arg.op.socket_op.type = type;
		arg.op.socket_op.protocol = protocol;

		fd = ioctl(fsocket_channel_fd, FSOCKET_IOC_SOCKET, &arg);
		if (fd < 0) {
			FSOCKET_DBG(FSOCKET_ERR, "FSOCKET:create light socket failed!\n");
		}
	} else {
		if (!real_socket)
			real_socket = dlsym(RTLD_NEXT, "socket");

		//fd =  SYSCALL(socket, family, type, protocoal);
		fd =  real_socket(family, type, protocol);
	}

	return fd;
}

int listen(int fd, int backlog)
{
	static int (*real_listen)(int, int) = NULL;
	int ret = 0;
	struct fsocket_ioctl_arg arg;

	if (!real_listen)
		real_listen = dlsym(RTLD_NEXT, "listen");

	if (fsocket_channel_fd != 0) {
		arg.fd = fd;
		arg.backlog = backlog;

		if (!fsocket_listen_fds[fd])
			fsocket_listen_fds[fd] = 1;

		//ret = ioctl(fsocket_channel_fd, FSOCKET_IOC_LISTEN, &arg);
		ret =  real_listen(fd, backlog);
		if (ret < 0) {
			FSOCKET_DBG(FSOCKET_ERR, "FSOCKET:Listen failed!\n");
			fsocket_listen_fds[fd] = 0;
		}

	} else {
		//ret =  SYSCALL(listen, fd, backlog);
		ret =  real_listen(fd, backlog);
	}

	return ret;
}

int listen_spawn(int fd)
{
	int ret = -1;
	struct fsocket_ioctl_arg arg;

	if (fsocket_channel_fd != 0) {
		arg.fd = fd;

		ret = ioctl(fsocket_channel_fd, FSOCKET_IOC_SPAWN, &arg);
		if (ret < 0) {
			FSOCKET_DBG(FSOCKET_ERR, "FSOCKET:Listen failed!\n");
		}
	}

	return ret;
}

int accept(int fd, struct sockaddr *addr, socklen_t *addr_len)
{
	static int (*real_accept)(int, struct sockaddr *, socklen_t *) = NULL;
	int ret = 0;
	struct fsocket_ioctl_arg arg;

	if (fsocket_channel_fd != 0) {
		arg.fd = fd;
		arg.op.accept_op.sockaddr = addr;
		arg.op.accept_op.sockaddr_len = addr_len;
		arg.op.accept_op.flags = 0;

		ret = ioctl(fsocket_channel_fd, FSOCKET_IOC_ACCEPT, &arg);
		if (ret < 0 && errno != EAGAIN) {
			FSOCKET_DBG(FSOCKET_ERR, "FSOCKET:Accept failed!\n");
		}
	} else {
		if (!real_accept)
			real_accept = dlsym(RTLD_NEXT, "accept");
		//ret =  SYSCALL(accept, fd, addr, addr_len);
		ret = real_accept(fd, addr, addr_len);
	}

	return ret;
}

int accept4(int fd, struct sockaddr *addr, socklen_t *addr_len, int flags)
{
	static int (*real_accept)(int, struct sockaddr *, socklen_t *) = NULL;
	int ret = 0;
	struct fsocket_ioctl_arg arg;

	if (fsocket_channel_fd != 0) {
		arg.fd = fd;
		arg.op.accept_op.sockaddr = addr;
		arg.op.accept_op.sockaddr_len = addr_len;
		arg.op.accept_op.flags = flags;

		ret = ioctl(fsocket_channel_fd, FSOCKET_IOC_ACCEPT, &arg);
		if (ret < 0 && errno != EAGAIN) {
			FSOCKET_DBG(FSOCKET_ERR, "FSOCKET:Accept failed!\n");
		}
	} else {
		if (!real_accept)
			real_accept = dlsym(RTLD_NEXT, "accept4");
		//ret =  SYSCALL(accept, fd, addr, addr_len);
		ret = real_accept(fd, addr, addr_len);
	}

	return ret;
}
int close(int fd)
{
	static int (*real_close)(int) = NULL;
	int ret;
	struct fsocket_ioctl_arg arg;

	if (fsocket_channel_fd != 0) {
		arg.fd = fd;

		if (fsocket_listen_fds[fd])
			fsocket_listen_fds[fd] = 0;

		ret = ioctl(fsocket_channel_fd, FSOCKET_IOC_CLOSE, &arg);
		if (ret < 0) {
			FSOCKET_DBG(FSOCKET_ERR, "FSOCKET:Close failed!\n");
		}
	} else {
		if (!real_close)
			real_close = dlsym(RTLD_NEXT, "close");
		//ret = SYSCALL(close, fd);
		ret = real_close(fd);
	}

	return ret;
}
/*

int SYSCALL_DEFINE(write, int fd, char *buf, int buf_len)
{
	int ret;
	struct fsocket_ioctl_arg arg;

	if (fsocket_channel_fd != 0) {
		arg.fd = fd;
		arg.op.io_op.buf = buf;
		arg.op.io_op.buf_len = buf_len;

		ret = ioctl(fsocket_channel_fd, FSOCKET_IOC_WRITE, &arg);
		if (ret < 0) {
			FSOCKET_DBG(FSOCKET_ERR, "FSOCKET:Write failed!\n");
		}
	} else {
		ret = SYSCALL(write, buf, buf_len);
	}

	return ret;
}


int SYSCALL_DEFINE(read, int fd, char *buf, int buf_len)
{
	int ret;
	struct fsocket_ioctl_arg arg;

	if (fsocket_channel_fd != 0) {
		arg.fd = fd;
		arg.op.io_op.buf = buf;
		arg.op.io_op.buf_len = buf_len;

		ret = ioctl(fsocket_channel_fd, FSOCKET_IOC_READ, &arg);
		if (ret < 0) {
			FSOCKET_DBG(FSOCKET_ERR, "FSOCKET:Read failed!\n");
		}
	} else {
		ret = SYSCALL(read, buf, buf_len);
	}

	return ret;
}

*/

int epoll_ctl(int efd, int cmd, int fd, struct epoll_event *ev)
{
	static int (*real_epoll_ctl)(int, int, int, struct epoll_event *) = NULL;
	int ret;
	struct fsocket_ioctl_arg arg;

	if (fsocket_channel_fd != 0) {
		arg.fd = fd;
		arg.op.spawn_op.cpu = -1;

		if (fsocket_listen_fds[fd] && cmd == EPOLL_CTL_ADD) {
			ret = ioctl(fsocket_channel_fd, FSOCKET_IOC_SPAWN, &arg);
			if (ret < 0) {
				FSOCKET_DBG(FSOCKET_ERR, "FSOCKET: spawn failed!\n");
				//FIXME: as of now, ignore the spawn err.
				//return ret;
			}
		}

		arg.op.epoll_op.epoll_fd = efd;
		arg.op.epoll_op.ep_ctl_cmd = cmd;
		arg.op.epoll_op.ev = ev;

		ret = ioctl(fsocket_channel_fd, FSOCKET_IOC_EPOLL_CTL, &arg);
		if (ret < 0) {
			FSOCKET_DBG(FSOCKET_ERR, "FSOCKET: epoll_ctl failed!\n");
			return ret;
		}	
		

	} else {
		if (!real_epoll_ctl)
			real_epoll_ctl = dlsym(RTLD_NEXT, "epoll_ctl");
		//ret = SYSCALL(epoll_ctl, efd, cmd, fd, ev);
		ret = real_epoll_ctl(efd, cmd, fd, ev);
	}

	return ret;
}
