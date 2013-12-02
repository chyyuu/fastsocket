/*
 *  include/linux/eventpoll.h ( Efficent event polling implementation )
 *  Copyright (C) 2001,...,2006	 Davide Libenzi
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  Davide Libenzi <davidel@xmailserver.org>
 *
 */

#ifndef _LINUX_EVENTPOLL_H
#define _LINUX_EVENTPOLL_H

/* For O_CLOEXEC */
#include <linux/fcntl.h>
#include <linux/types.h>
#include <linux/poll.h>

/* Flags for epoll_create1.  */
#define EPOLL_CLOEXEC O_CLOEXEC

/* Valid opcodes to issue to sys_epoll_ctl() */
#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLL_CTL_MOD 3

/* Set the One Shot behaviour for the target file descriptor */
#define EPOLLONESHOT (1 << 30)

/* Set the Edge Triggered behaviour for the target file descriptor */
#define EPOLLET (1 << 31)

/* 
 * On x86-64 make the 64bit structure have the same alignment as the
 * 32bit structure. This makes 32bit emulation easier.
 *
 * UML/x86_64 needs the same packing as x86_64
 */
#ifdef __x86_64__
#define EPOLL_PACKED __attribute__((packed))
#else
#define EPOLL_PACKED
#endif

struct epoll_event {
	__u32 events;
	__u64 data;
} EPOLL_PACKED;

#ifdef __KERNEL__

/* Forward declarations to avoid compiler errors */
struct file;


#ifdef CONFIG_EPOLL

//XIAOFENG6

/* Epoll private bits inside the event mask */
#define EP_PRIVATE_BITS (EPOLLONESHOT | EPOLLET)

/* Maximum number of nesting allowed inside epoll sets */
#define EP_MAX_NESTS 4

/* Maximum msec timeout value storeable in a long int */
#define EP_MAX_MSTIMEO min(1000ULL * MAX_SCHEDULE_TIMEOUT / HZ, (LONG_MAX - 999ULL) / HZ)

#define EP_MAX_EVENTS (INT_MAX / sizeof(struct epoll_event))

#define EP_UNACTIVE_PTR ((void *) -1L)

#define EP_ITEM_COST (sizeof(struct epitem) + sizeof(struct eppoll_entry))


struct epoll_filefd {
	struct file *file;
	int fd;
};

/*
 * Structure used to track possible nested calls, for too deep recursions
 * and loop cycles.
 */
struct nested_call_node {
	struct list_head llink;
	void *cookie;
	void *ctx;
};

/*
 * This structure is used as collector for nested calls, to check for
 * maximum recursion dept and loop cycles.
 */
struct nested_calls {
	struct list_head tasks_call_list;
	spinlock_t lock;
};

/*
 * Each file descriptor added to the eventpoll interface will
 * have an entry of this type linked to the "rbr" RB tree.
 */
struct epitem {
	/* RB tree node used to link this structure to the eventpoll RB tree */
	struct rb_node rbn;

	/* List header used to link this structure to the eventpoll ready list */
	struct list_head rdllink;

	/*
	 * Works together "struct eventpoll"->ovflist in keeping the
	 * single linked chain of items.
	 */
	struct epitem *next;

	/* The file descriptor information this item refers to */
	struct epoll_filefd ffd;

	/* Number of active wait queue attached to poll operations */
	int nwait;

	/* List containing poll wait queues */
	struct list_head pwqlist;

	/* The "container" of this item */
	struct eventpoll *ep;

	/* List header used to link this item to the "struct file" items list */
	struct list_head fllink;

	/* The structure that describe the interested events and the source fd */
	struct epoll_event event;
};

/*
 * This structure is stored inside the "private_data" member of the file
 * structure and rapresent the main data sructure for the eventpoll
 * interface.
 */
struct eventpoll {
	/* Protect the this structure access */
	spinlock_t lock;

	/*
	 * This mutex is used to ensure that files are not removed
	 * while epoll is using them. This is held during the event
	 * collection loop, the file cleanup path, the epoll file exit
	 * code and the ctl operations.
	 */
	struct mutex mtx;

	/* Wait queue used by sys_epoll_wait() */
	wait_queue_head_t wq;

	/* Wait queue used by file->poll() */
	wait_queue_head_t poll_wait;

	/* List of ready file descriptors */
	struct list_head rdllist;

	/* RB tree root used to store monitored fd structs */
	struct rb_root rbr;

	/*
	 * This is a single linked list that chains all the "struct epitem" that
	 * happened while transfering ready events to userspace w/out
	 * holding ->lock.
	 */
	struct epitem *ovflist;

	/* The user that created the eventpoll descriptor */
	struct user_struct *user;
};

/* Wait structure used by the poll hooks */
struct eppoll_entry {
	/* List header used to link this structure to the "struct epitem" */
	struct list_head llink;

	/* The "base" pointer is set to the container "struct epitem" */
	struct epitem *base;

	/*
	 * Wait queue item that will be linked to the target file wait
	 * queue head.
	 */
	wait_queue_t wait;

	/* The wait queue head that linked the "wait" wait queue item */
	wait_queue_head_t *whead;
};

/* Wrapper struct used by poll queueing */
struct ep_pqueue {
	poll_table pt;
	struct epitem *epi;
};

/* Used by the ep_send_events() function as callback private data */
struct ep_send_events_data {
	int maxevents;
	struct epoll_event __user *events;
};

/* Setup the structure that is used as key for the RB tree */
static inline void ep_set_ffd(struct epoll_filefd *ffd,
			      struct file *file, int fd)
{
	ffd->file = file;
	ffd->fd = fd;
}

/* Compare RB tree keys */
static inline int ep_cmp_ffd(struct epoll_filefd *p1,
			     struct epoll_filefd *p2)
{
	return (p1->file > p2->file ? +1:
	        (p1->file < p2->file ? -1 : p1->fd - p2->fd));
}

/* Tells us if the item is currently linked */
static inline int ep_is_linked(struct list_head *p)
{
	return !list_empty(p);
}

/* Get the "struct epitem" from a wait queue pointer */
static inline struct epitem *ep_item_from_wait(wait_queue_t *p)
{
	return container_of(p, struct eppoll_entry, wait)->base;
}

/* Get the "struct epitem" from an epoll queue wrapper */
static inline struct epitem *ep_item_from_epqueue(poll_table *p)
{
	return container_of(p, struct ep_pqueue, pt)->epi;
}

/* Tells if the epoll_ctl(2) operation needs an event copy from userspace */
static inline int ep_op_has_event(int op)
{
	return op != EPOLL_CTL_DEL;
}

//XIAOFENG6

extern int ep_remove(struct eventpoll *ep, struct epitem *epi);
extern int ep_insert(struct eventpoll *ep, struct epoll_event *event, 
		struct file *tfile, int fd);
extern int ep_modify(struct eventpoll *ep, struct epitem *epi, 
		struct epoll_event *event);
extern void ep_poll_safewake(wait_queue_head_t *wq);
extern int ep_alloc(struct eventpoll **pep);
extern void ep_free(struct eventpoll *ep);
extern void ep_rbtree_insert(struct eventpoll *ep, struct epitem *epi);
extern void ep_unregister_pollwait(struct eventpoll *ep, struct epitem *epi);
extern void ep_ptable_queue_proc(struct file *file, wait_queue_head_t *whead, 
	poll_table *pt);
extern int ep_poll(struct eventpoll *ep, 
	struct epoll_event __user *events, int maxevents, long timeout);
extern struct epitem *ep_find(struct eventpoll *ep, struct file *file, int fd);
extern int max_user_watches;
extern struct kmem_cache *epi_cache;

//XIAOFENG6

/* Used to initialize the epoll bits inside the "struct file" */
static inline void eventpoll_init_file(struct file *file)
{
	INIT_LIST_HEAD(&file->f_ep_links);
}


/* Used to release the epoll bits inside the "struct file" */
void eventpoll_release_file(struct file *file);

/*
 * This is called from inside fs/file_table.c:__fput() to unlink files
 * from the eventpoll interface. We need to have this facility to cleanup
 * correctly files that are closed without being removed from the eventpoll
 * interface.
 */
static inline void eventpoll_release(struct file *file)
{

	/*
	 * Fast check to avoid the get/release of the semaphore. Since
	 * we're doing this outside the semaphore lock, it might return
	 * false negatives, but we don't care. It'll help in 99.99% of cases
	 * to avoid the semaphore lock. False positives simply cannot happen
	 * because the file in on the way to be removed and nobody ( but
	 * eventpoll ) has still a reference to this file.
	 */
	if (likely(list_empty(&file->f_ep_links)))
		return;

	/*
	 * The file is being closed while it is still linked to an epoll
	 * descriptor. We need to handle this by correctly unlinking it
	 * from its containers.
	 */
	eventpoll_release_file(file);
}

#else

static inline void eventpoll_init_file(struct file *file) {}
static inline void eventpoll_release(struct file *file) {}

#endif

#endif /* #ifdef __KERNEL__ */

#endif /* #ifndef _LINUX_EVENTPOLL_H */

