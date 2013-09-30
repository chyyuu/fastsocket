#ifndef _PROTO_INOTIFY_H
#define _PROTO_INOTIFY_H

#include <types/inotify.h>

int init_inotify_instance(void);
int process_inotify(int fd);
int reload_backend_server(struct proxy *px);
int install_inotify_watch(struct proxy *po);
static int inline enable_inotify(void)
{
        return EV_FD_SET(global.inotify_fd, DIR_RD);
}
#endif
