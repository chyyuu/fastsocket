#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <errno.h>

#include "libsocket.h"

static int fsocket_channel_fd = -1;
static int fsocket_epoll_fd = -1;

#define SYSCALL_DEFINE(name, ...) __wrap_##name(__VA_ARGS__)
#define SYSCALL(name, ...)  __real_##name(__VA_ARGS__)


#define FSOCKET_DBG(level, msg, ...) \
do {\
	fprintf(stderr, "FATSOCKET LIBRARY:" msg, ##__VA_ARGS__);\
}while(0)

#define MAX_LISTEN_FD	65536

//TODO: Need Lock for Multi-thread programme

static int fsocket_listen_fds[MAX_LISTEN_FD];

__attribute__((constructor))
void fastsocket_init(void)
{
	int ret = 0;
	int i;

	fsocket_channel_fd = open("/dev/fastsocket_channel", O_RDONLY);
	if (fsocket_channel_fd < 0) {
		FSOCKET_DBG(FSOCKET_ERR, "Open fastsocket channel failed, please CHECK\n");
		exit(-1);
	}

	for (i = 0; i < MAX_LISTEN_FD; i++)
		fsocket_listen_fds[i] = 0;

	return;
}

__attribute__((destructor))
void fastsocket_uninit(void)
{
	close(fsocket_channel_fd);

	return;
}

int SYSCALL_DEFINE(socket, int family, int type, int protocol)
{
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
		fd =  SYSCALL(socket, family, type, protocol);
	}

	return fd;
}

int SYSCALL_DEFINE(listen, int fd, int backlog)
{
	int ret = 0;
	struct fsocket_ioctl_arg arg;

	if (fsocket_channel_fd != 0) {
		arg.fd = fd;
		arg.backlog = backlog;

		if (!fsocket_listen_fds[fd])
			fsocket_listen_fds[fd] = 1;
		else
			return -1;

		//ret = ioctl(fsocket_channel_fd, FSOCKET_IOC_LISTEN, &arg);
		ret =  SYSCALL(listen, fd, backlog);
		if (ret < 0) {
			FSOCKET_DBG(FSOCKET_ERR, "FSOCKET:Listen failed!\n");
			fsocket_listen_fds[fd] = 0;
		}

	} else {
		ret =  SYSCALL(listen, fd, backlog);
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

int SYSCALL_DEFINE(accept, int fd, struct sockaddr *addr, socklen_t *addr_len)
{
	int ret = 0;
	struct fsocket_ioctl_arg arg;

	if (fsocket_channel_fd != 0) {
		arg.fd = fd;
		arg.op.accept_op.sockaddr = addr;
		arg.op.accept_op.sockaddr_len = addr_len;

		ret = ioctl(fsocket_channel_fd, FSOCKET_IOC_ACCEPT, &arg);
		if (ret < 0 && errno != EAGAIN) {
			FSOCKET_DBG(FSOCKET_ERR, "FSOCKET:Accept failed!\n");
		}
	} else {
		ret =  SYSCALL(accept, fd, addr, addr_len);
	}

	return ret;
}

int SYSCALL_DEFINE(close, int fd)
{
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
		ret = SYSCALL(close, fd);
	}

	return ret;
}

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

int SYSCALL_DEFINE(epoll_ctl, int efd, int cmd, int fd, struct epoll_event *ev)
{
	int ret;
	struct fsocket_ioctl_arg arg;

	if (fsocket_channel_fd != 0) {
		arg.fd = fd;
		arg.op.epoll_op.epoll_fd = efd;
		arg.op.epoll_op.ep_ctl_cmd = cmd;
		arg.op.epoll_op.ev = ev;

		if (fsocket_listen_fds[fd]) {
			ret = ioctl(fsocket_channel_fd, FSOCKET_IOC_SPAWN, &arg);
			if (ret < 0) {
				FSOCKET_DBG(FSOCKET_ERR, "FSOCKET:Spawn failed!\n");
				//FIXME: as of now, ignore the spawn err.
				//return ret;
			}
		}

		ret = ioctl(fsocket_channel_fd, FSOCKET_IOC_EPOLL_CTL, &arg);
		if (ret < 0) {
			FSOCKET_DBG(FSOCKET_ERR, "FSOCKET:epoll_ctl failed!\n");
			return ret;
		}	
		

	} else {
		ret = SYSCALL(epoll_ctl, efd, cmd, fd, ev);
	}

	return ret;
}
