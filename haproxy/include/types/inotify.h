#ifndef _TYPES_INOTIFY_H
#define _TYPES_INOTIFY_H

#include <common/cfgparse.h>
#include <types/proxy.h>
#include <proto/log.h>

//backend notify or acl notify
#if 0
#define BACKEND_SERVER_INOTIFY_TYPE 1
#define ACL_INOTIFY_TYPE 2
struct inotify_info {
	int wd;
	struct proxy *px;
	int type;
};

#define INSTALL_INOTIFY_INFO(fd, px) ((inotify_info_tab[(fd)]).px = (px))

#endif 
#endif
