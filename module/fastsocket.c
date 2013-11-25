#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <linux/fs.h>
#include <linux/file.h>
#include <linux/miscdevice.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/inet_sock.h>
#include <net/inet_common.h>
#include <linux/wait.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/nsproxy.h>
#include <linux/file.h>
#include <linux/net.h>
#include <linux/eventpoll.h>
#include <linux/list.h>
#include <linux/syscalls.h>
#include <linux/cred.h>
#include <linux/fdtable.h>
#include <linux/mount.h>
#include <linux/types.h>
#include <linux/mutex.h>

#include <linux/fsnotify.h>

#include "fastsocket.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Xiaofeng Lin <sina.com>, SiXing Xiao <sina.com>");

MODULE_DESCRIPTION("Fast socket kernel module");

static int fsocket_debug_level = 5;
static int enable_listen_spawn = 0;
extern int enable_receive_flow_deliver;

module_param(fsocket_debug_level,int, 0);
module_param(enable_listen_spawn, int, 0);
module_param(enable_receive_flow_deliver, int, 0);

MODULE_PARM_DESC(enable_listen_spawn, " Control listen-spawn behavior: 0 = Disbale, 1 = Process affinity required, 2 = Autoset process affinity");
MODULE_PARM_DESC(fsocket_debug_level, " Debug level (0-6)");

int fsocket_get_dbg_level(void)
{
	return fsocket_debug_level;
}

#define DISABLE_LISTEN_SPAWN			0
#define ENABLE_LISTEN_SPAWN_REQUIRED_AFFINITY	1
#define ENABLE_LISTEN_SPAWN_AUTOSET_AFFINITY	2

static struct kmem_cache *socket_cachep = NULL;
extern struct kmem_cache *dentry_cache;

static struct vfsmount *sock_mnt;

static DEFINE_PER_CPU(int, fastsockets_in_use) = 0;
static DEFINE_PER_CPU(unsigned int, global_spawn_accept) = 0;

extern int inet_create(struct net *net, struct socket *sock, int protocol, int kern);

static int fsocket_filp_close(struct file *file);
static void fsock_release_sock(struct socket *sock);

static void fastsock_destroy_inode(struct inode *inode)
{
	DPRINTK(DEBUG, "Free inode 0x%p\n", inode);

	if (inode->i_mode & S_IFSOCK)
		fsock_release_sock(INODE_SOCKET(inode));
	else
		WARN_ON(1);

	kmem_cache_free(socket_cachep, container_of(inode, struct socket_alloc, vfs_inode));

	percpu_sub(fastsockets_in_use, 1);
}

static struct inode *fastsock_alloc_inode(struct super_block *sb)
{
	struct fsocket_alloc *ei;

	ei = kmem_cache_alloc(socket_cachep, GFP_KERNEL);
	if (!ei)
		return NULL;
	init_waitqueue_head(&ei->socket.wait);

	ei->socket.fasync_list = NULL;
	ei->socket.state = SS_UNCONNECTED;
	ei->socket.flags = 0;
	ei->socket.ops = NULL;
	ei->socket.sk = NULL;
	ei->socket.file = NULL;

	DPRINTK(DEBUG, "Allocate inode 0x%p\n", &ei->vfs_inode);

	return &ei->vfs_inode;
}

static const struct super_operations fastsockfs_ops = {
	.alloc_inode = fastsock_alloc_inode,
	.destroy_inode = fastsock_destroy_inode,
	.statfs = simple_statfs,
};

static int fastsockfs_get_sb(struct file_system_type *fs_type,
			 int flags, const char *dev_name, void *data,
			 struct vfsmount *mnt)
{
	//FIXME: How about MAGIC Number
	return get_sb_pseudo(fs_type, "fastsocket:", &fastsockfs_ops, 0x534F434C,
			     mnt);
}

static struct file_system_type fastsock_fs_type = {
	.name = "fastsockfs",
	.get_sb = fastsockfs_get_sb,
	.kill_sb = kill_anon_super,
};

static inline unsigned int fast_sock_poll(struct file *file, poll_table *wait)
{
	struct socket *sock;
	
	sock = (struct socket *)file->private_data;
	return sock->ops->poll(file, sock, wait);
}

static inline int fast_sock_close(struct inode *i_node, struct file *file)
{
	return fsocket_filp_close(file);
}

loff_t fast_sock_llseek(struct file *file, loff_t offset, int origin)
{
	return -ESPIPE;
}

static int fast_sock_open(struct inode *irrelevant, struct file *dontcare)
{
	return -ENXIO;
}

extern ssize_t sock_aio_read(struct kiocb *iocb, const struct iovec *iov,
		unsigned long nr_segs, loff_t pos);

extern ssize_t sock_aio_write(struct kiocb *iocb, const struct iovec *iov,
		unsigned long nr_segs, loff_t pos);

static inline ssize_t fast_sock_read(struct kiocb *iocb, const struct iovec *iov,
		unsigned long nr_segs, loff_t pos)
{
	ssize_t ret;
	ret = sock_aio_read(iocb, iov, nr_segs, pos);
	DPRINTK(DEBUG, "Read %ld\n", ret);
	return ret;
}

static inline ssize_t fast_sock_write(struct kiocb *iocb, const struct iovec *iov, 
		unsigned long nr_segs, loff_t pos)
{
	ssize_t ret;
	ret = sock_aio_write(iocb, iov, nr_segs, pos);
	DPRINTK(DEBUG, "Write %ld\n", ret);
	return ret;
}

static inline long fast_sock_ioctl(struct file *file, unsigned cmd, unsigned long arg)
{
	DPRINTK(INFO, "Do!\n");
	return -EINVAL;
}

static inline long fast_compate_sock_ioctl(struct file *file, unsigned cmd, unsigned long arg)
{
	DPRINTK(INFO, "Do!\n");
	return -EINVAL;
}

static inline int fast_sock_mmap(struct file *file, struct vm_area_struct *vma)
{
	DPRINTK(INFO, "Do!\n");
	return -EINVAL;
}

static inline int fast_sock_fasync(int fd, struct file *filp, int on)
{
	DPRINTK(INFO, "Do!\n");
	return -EINVAL;
}

static inline ssize_t fast_sock_sendpage(struct file *file, struct page *page, 
		int offset, size_t size, loff_t *ppos, int more)
{
	DPRINTK(INFO, "Do!\n");
	return -EINVAL;
}

extern ssize_t generic_splice_sendpage(struct pipe_inode_info *pipe, 
		struct file *out, loff_t *ppos, size_t len, unsigned int flags);
extern ssize_t sock_splice_read(struct file *file, loff_t *ppos, 
		struct pipe_inode_info *pipe, size_t len, unsigned int flags);

static inline ssize_t fast_sock_splice_write(struct pipe_inode_info *pipe, 
		struct file *out, loff_t *ppos, size_t len, unsigned int flags)
{
	ssize_t ret;
	ret = generic_splice_sendpage(pipe, out, ppos, len, flags);
	DPRINTK(INFO, "Splice wirte %ld\n", ret);
	return ret;
}

static inline ssize_t fast_sock_splice_read(struct file *file, loff_t *ppos, 
		struct pipe_inode_info *pipe, size_t len, unsigned int flags)
{
	ssize_t ret;
	ret = sock_splice_read(file, ppos, pipe, len, flags);
	DPRINTK(INFO, "Splice read %ld\n", ret);
	return ret;
}

static const struct file_operations socket_file_ops = {
	.owner = 	THIS_MODULE,
	.llseek =	fast_sock_llseek,
	.aio_read = 	fast_sock_read,
	.aio_write =	fast_sock_write,
	.poll =		fast_sock_poll,
	.unlocked_ioctl = fast_sock_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = fast_compate_sock_ioctl,
#endif
	.mmap =		fast_sock_mmap,
	.open =		fast_sock_open,	/* special open code to disallow open via /proc */
	.release =	fast_sock_close,
	.fasync =	fast_sock_fasync,
	.sendpage =	fast_sock_sendpage,
	.splice_write = fast_sock_splice_write,
	.splice_read =	fast_sock_splice_read,
};

static char *fastsockfs_dynamic_dname(struct dentry *dentry, char *buffer, int buflen,
			const char *fmt, ...)
{
	va_list args;
	char temp[64];
	int sz;

	va_start(args, fmt);
	sz = vsnprintf(temp, sizeof(temp), fmt, args) + 1;
	va_end(args);

	if (sz > sizeof(temp) || sz > buflen)
		return ERR_PTR(-ENAMETOOLONG);

	buffer += buflen - sz;
	return memcpy(buffer, temp, sz);
}

static char *fastsockfs_dname(struct dentry *dentry, char *buffer, int buflen)
{
	return fastsockfs_dynamic_dname(dentry, buffer, buflen, "socket:[%lu]",
				dentry->d_inode->i_ino);
}

static const struct dentry_operations fastsockfs_dentry_operations = {
	.d_dname  = fastsockfs_dname,
};

static void __put_unused_fd(struct files_struct *files, unsigned int fd)
{
	struct fdtable *fdt = files_fdtable(files);
	__FD_CLR(fd, fdt->open_fds);
	if (fd < files->next_fd)
		files->next_fd = fd;
}

static inline void fsock_release_sock(struct socket *sock)
{
	if (sock->ops) {
		DPRINTK(DEBUG, "Release inode socket 0x%p\n", SOCK_INODE(sock));
		sock->ops->release(sock);
		sock->ops = NULL;
	}
}

static int __fsocket_filp_close(struct file *file)
{	
	struct dentry *dentry = file->f_path.dentry;

	if (atomic_long_dec_and_test(&file->f_count)) {
		
		eventpoll_release(file);

		file->private_data = NULL;
		file->f_path.dentry = NULL;
		file->f_path.mnt = NULL;

		put_empty_filp(file);

		if (dentry) {
			DPRINTK(DEBUG, "Release dentry 0x%p[%d]\n", dentry, atomic_read(&dentry->d_count));
			DPRINTK(DEBUG, "Release inode 0x%p[%d]\n", dentry->d_inode, atomic_read(&dentry->d_inode->i_count));
		}
		else {
			DPRINTK(ERR, "No dentry for file 0x%p\n", file);
		}

		dput(dentry);
		return 0;

	}
	else {
		DPRINTK(DEBUG, "Next time to release file 0x%p[%ld]\n", file, atomic_long_read(&file->f_count));
		return 1;
	}
}

static inline int fsocket_filp_close(struct file *file)
{
	struct file *sfile;
	int retval;

	sfile = file->sub_file;

	DPRINTK(DEBUG, "Close file 0x%p\n", file);

	retval = __fsocket_filp_close(file);

	if (sfile && !retval) {
		DPRINTK(DEBUG, "Close spawn socket file 0x%p\n", sfile);
		__fsocket_filp_close(sfile);
	}

	return 0;
}

static int fsocket_close(unsigned int fd)
{
	struct file *filp;
	struct files_struct *files = current->files;
	struct fdtable *fdt;
	int retval = 0;

	spin_lock(&files->file_lock);
	fdt = files_fdtable(files);
	if (fd >= fdt->max_fds)
		goto out_unlock;
	filp = fdt->fd[fd];
	if (!filp)
		goto out_unlock;
	rcu_assign_pointer(fdt->fd[fd], NULL);
	FD_CLR(fd, fdt->close_on_exec);
	__put_unused_fd(files, fd);
	spin_unlock(&files->file_lock);

	retval = fsocket_filp_close(filp);

	return retval;

out_unlock:
	spin_unlock(&files->file_lock);
	return -EBADF;
}

#define FSOCKET_INODE_START	( 1 << 12 )

static struct socket *fsocket_alloc_socket(void)
{
	struct socket *sock;
	struct inode *inode = NULL;

	//FIXME: Just guess this inode number is not something really matters.
	static unsigned int last_ino = FSOCKET_INODE_START;

	sock = (struct socket *)kmem_cache_alloc(socket_cachep, GFP_KERNEL);

	if (sock != NULL) {

		static const struct inode_operations empty_iops;
		static const struct file_operations empty_fops;

		init_waitqueue_head(&sock->wait);

		sock->fasync_list = NULL;
		sock->state = SS_UNCONNECTED;
		sock->flags = 0;
		sock->ops = NULL;
		sock->sk = NULL;
		sock->file = NULL;

		sock->type = 0;

		inode = SOCK_INODE(sock);

		inode->i_op = &empty_iops;
		inode->i_fop = &empty_fops;
		inode->i_sb = sock_mnt->mnt_sb;
		atomic_set(&inode->i_count, 1);

		INIT_LIST_HEAD(&inode->i_list);
		INIT_LIST_HEAD(&inode->i_sb_list);

		inode->i_ino = ++last_ino;
		inode->i_state = 0;

		kmemcheck_annotate_bitfield(sock, type);
		inode->i_mode = S_IFSOCK | S_IRWXUGO;
		inode->i_uid = current_fsuid();
		inode->i_gid = current_fsgid();

		percpu_add(fastsockets_in_use, 1);

		DPRINTK(DEBUG, "Allocat inode 0x%p\n", inode);
	}

	return sock;
}

#define DNAME_INLINE_LEN (sizeof(struct dentry)-offsetof(struct dentry,d_iname))

static struct dentry *fsock_d_alloc(struct socket *sock, struct dentry *parent, const struct qstr *name)
{
	struct dentry *dentry;
	char *dname;
	struct inode *inode;

	dentry = kmem_cache_alloc(dentry_cache, GFP_KERNEL);
	if (!dentry)
		return NULL;

	DPRINTK(DEBUG, "\tAllocat dentry 0x%p\n", dentry);
	
	if (name->len > DNAME_INLINE_LEN-1) {
		dname = kmalloc(name->len + 1, GFP_KERNEL);
		if (!dname)
			return NULL;
	} else  {
		dname = dentry->d_iname;
	}

	dentry->d_name.name = dname;

	dentry->d_name.len = name->len;
	dentry->d_name.hash = name->hash;
	memcpy(dname, name->name, name->len);
	dname[name->len] = 0;

	atomic_set(&dentry->d_count, 1);
	dentry->d_flags = DCACHE_UNHASHED;
	spin_lock_init(&dentry->d_lock);
	dentry->d_inode = NULL;
	dentry->d_parent = NULL;
	dentry->d_sb = NULL;
	dentry->d_op = NULL;
	dentry->d_fsdata = NULL;
	INIT_HLIST_NODE(&dentry->d_hash);
	INIT_LIST_HEAD(&dentry->d_lru);
	INIT_LIST_HEAD(&dentry->d_subdirs);
	INIT_LIST_HEAD(&dentry->d_alias);

	INIT_LIST_HEAD(&dentry->d_u.d_child);

	inode = SOCK_INODE(sock);

	dentry->d_sb = inode->i_sb;
	dentry->d_parent = NULL;
	dentry->d_flags |= DCACHE_FASTSOCKET | DCACHE_DISCONNECTED;
	dentry->d_inode = inode;

	dentry->d_op = &fastsockfs_dentry_operations;

	return dentry;
}

static int fsock_alloc_file(struct socket *sock, struct file **f, int flags)
{
	int fd;
	struct qstr name = { .name = "" };
	struct path path;
	struct file *file;

	fd = get_unused_fd_flags(flags);

	if (unlikely(fd < 0)) {
		printk(KERN_ERR "Get unused fd failed\n");
		return fd;
	}

	//Initialize path structure
	
	path.dentry = fsock_d_alloc(sock, NULL, &name);
	if (unlikely(!path.dentry)) {
		printk(KERN_ERR "Allocate dentry failed\n");
		put_unused_fd(fd);
		return -ENOMEM;
	}

	path.mnt = sock_mnt;

	SOCK_INODE(sock)->i_fop = &socket_file_ops;

	file = get_empty_filp();
	
	DPRINTK(DEBUG, "Allocate file 0x%p\n", file);

	if (unlikely(!file)) {
		printk(KERN_ERR "Allocate empty file failed\n");
		atomic_inc(&path.dentry->d_inode->i_count);
		dput(path.dentry);
		put_unused_fd(fd);
		return -ENFILE;
	}

	file->f_path = path;
	file->f_mapping = path.dentry->d_inode->i_mapping;
	file->f_mode = FMODE_READ | FMODE_WRITE | FMODE_FASTSOCKET;
	file->f_op = &socket_file_ops;

	sock->file = file;

	file->f_flags = O_RDWR | (flags & O_NONBLOCK);
	file->f_pos = 0;
	file->private_data = sock;

	//Extra Initilization For Fastsocket
	file->sub_file = NULL;
	file->epoll_item = NULL;

	*f = file;

	return fd;
}

static int fsock_map_fd(struct socket *sock, int flags)
{
	struct file *newfile;

	int fd = fsock_alloc_file(sock, &newfile, flags);

	if (likely(fd >= 0))
		fd_install(fd, newfile);

	return fd;
}

static void fsocket_copy_socket(struct socket *oldsock, struct socket *newsock)
{
	newsock->sk->sk_reuse = oldsock->sk->sk_reuse;
}

static int fsocket_spawn_clone(int fd, struct socket *oldsock, struct socket **newsock)
{
	struct socket *sock;
	//struct tcp_sock *tp;
	struct file *ofile, *nfile, *sfile;
	struct qstr name = { .name = "" };
	struct path path;

	int err = 0;

	ofile = oldsock->file;

	/* 
	 * Allocate file for local spawned listen socket.
	*/

	DPRINTK(DEBUG, "Spawn inode 0x%p\n", SOCK_INODE(oldsock));

	sfile = get_empty_filp();
	if (sfile == NULL) {
		err = -ENOMEM;
		printk(KERN_ERR "Spawn sub listen socket alloc file failed\n");
		goto out;
	}
	
	DPRINTK(DEBUG, "Allocate sub listen socket file 0x%p\n", sfile);

	sock = fsocket_alloc_socket();
	if (sock == NULL) {
		printk(KERN_ERR "Allocate New Socket failed\n");
		err = -ENOMEM;
		put_empty_filp(sfile);
		goto out;
	}	

	sock->type = oldsock->type;

	err = inet_create(current->nsproxy->net_ns, sock, 0, 0);
	if (err < 0) {
		printk(KERN_ERR "Initialize Inet Socket failed\n");
		put_empty_filp(sfile);
		fsock_release_sock(sock);
		goto out;
	}

	fsocket_copy_socket(oldsock, sock);

	//tp = tcp_sk(sock->sk);
	//TODO: Default TCP OPT For Fastsocket.
	//tp->nonagle |= TCP_NAGLE_OFF | TCP_NAGLE_PUSH;

	path.dentry = fsock_d_alloc(sock, NULL, &name);
	if (unlikely(!path.dentry)) {
		err = -ENOMEM;
		printk(KERN_ERR "Spawn listen socket alloc dentry failed\n");
		put_empty_filp(sfile);
		fsock_release_sock(sock);
		goto out;
	}
	
	path.mnt = sock_mnt;

	sfile->f_path = path;
	sfile->f_mapping = NULL;

	sfile->f_mode = FMODE_READ | FMODE_WRITE | FMODE_FASTSOCKET;
	sfile->f_op = &socket_file_ops;
	sfile->f_flags = O_RDWR | O_NONBLOCK;
	sfile->f_pos = 0;
	sfile->private_data = sock;

	sfile->sub_file = NULL;
	sfile->epoll_item = NULL;

	//Initialize file at last, so, release_sock can release socket inode.
	sock->file = sfile;

	/* 
	 * Allocate file copy for global listen socket.
	*/

	nfile = get_empty_filp();
	if (nfile == NULL) {
		err = -ENOMEM;
		printk(KERN_ERR "Spawn global listen socket alloc file failed\n");
		__fsocket_filp_close(sfile);
		goto out;
	}

	DPRINTK(DEBUG, "Allocate new listen socket file 0x%p\n", nfile);

	path.dentry = fsock_d_alloc(oldsock, NULL, &name);
	if (unlikely(!path.dentry)) {
		err = -ENOMEM;
		printk(KERN_ERR "Spawn listen socket alloc dentry failed\n");
		put_empty_filp(nfile);
		__fsocket_filp_close(sfile);
		goto out;
	}

	path.mnt = sock_mnt;

	nfile->f_path = path;
	nfile->f_mapping = path.dentry->d_inode->i_mapping;

	nfile->f_mode = ofile->f_mode;
	nfile->f_op = ofile->f_op;
	nfile->f_flags = ofile->f_flags;
	nfile->f_pos = ofile->f_pos;
	nfile->private_data = oldsock;

	nfile->sub_file = sfile;
	nfile->epoll_item = NULL;

	//Add i_count for this socket inode.
	atomic_inc(&SOCK_INODE(oldsock)->i_count);

	fd_reinstall(fd, nfile);

	DPRINTK(DEBUG, "Close old socket file 0x%p\n", ofile);
	__fsocket_filp_close(ofile);
	
	DPRINTK(DEBUG, "Clone new socket %d\n", err);

	*newsock = sock;

	goto out;

out:
	return err;
}

static int fsocket_socket(int flags)
{
	struct socket *sock;
	//struct tcp_sock *tp;

	int err = 0;

	if ( flags & ~( SOCK_CLOEXEC | SOCK_NONBLOCK)) {
		printk(KERN_ERR "Unsupported Socket Flags For Fastsocket\n");
		err = -EINVAL;
		goto out;
	}
	
	sock = fsocket_alloc_socket();
	
	if (sock == NULL) {
		printk(KERN_ERR "Allocate New Socket failed\n");
		err = -ENOMEM;
		goto out;
	}	
	
	sock->type = SOCK_STREAM;

	err = inet_create(current->nsproxy->net_ns, sock, 0, 0);

	if (err < 0) {
		printk(KERN_ERR "Initialize Inet Socket failed\n");
		goto release_sock;
	}


	//tp = tcp_sk(sock->sk);
	//FIXME: Default TCP OPT For Fastsocket.
	//tp->nonagle |= TCP_NAGLE_OFF | TCP_NAGLE_PUSH;

	err = fsock_map_fd(sock, flags);

	if (err < 0) {
		printk(KERN_ERR "Map Socket FD failed\n");
		goto release_sock;
	}

	goto out;

release_sock:
	fsock_release_sock(sock);

out:
	return err;

}

static int fsocket_ep_insert(struct eventpoll *ep, struct epoll_event *event, struct file *tfile, int fd)
{
	int error, revents, pwake = 0;
	unsigned long flags;
	struct epitem *epi;
	struct ep_pqueue epq;

	DPRINTK(DEBUG, "Add socket %d to epoll\n", fd);

	if (unlikely(atomic_read(&ep->user->epoll_watches) >=
		     max_user_watches))
		return -ENOSPC;

	if (!(epi = kmem_cache_alloc(epi_cache, GFP_KERNEL)))
		return -ENOMEM;

	/* Item initialization follow here ... */
	INIT_LIST_HEAD(&epi->rdllink);
	INIT_LIST_HEAD(&epi->fllink);
	INIT_LIST_HEAD(&epi->pwqlist);
	epi->ep = ep;
	ep_set_ffd(&epi->ffd, tfile, fd);
	epi->event = *event;
	epi->nwait = 0;
	epi->next = EP_UNACTIVE_PTR;
	
	/* save epitem in file struct */
	tfile->epoll_item = epi;

	/* Initialize the poll table using the queue callback */
	epq.epi = epi;
	init_poll_funcptr(&epq.pt, ep_ptable_queue_proc);

	//XIAOFENG6
	revents = tfile->f_op->poll(tfile, &epq.pt);
	//XIAOFENG6

	/*
 	 * We have to check if something went wrong during the poll wait queue
  	 * install process. Namely an allocation for a wait queue failed due
	 * high memory pressure.
 	*/
	error = -ENOMEM;
	if (epi->nwait < 0)
		goto error_unregister;


	/* Add the current item to the list of active epoll hook for this file */
	spin_lock(&tfile->f_lock);
	list_add_tail(&epi->fllink, &tfile->f_ep_links);
	spin_unlock(&tfile->f_lock);

	/*
  	 * Add the current item to the RB tree. All RB tree operations are
  	 * protected by "mtx", and ep_insert() is called with "mtx" held.
  	 */
	ep_rbtree_insert(ep, epi);

	/* We have to drop the new item inside our item list to keep track of it */
	spin_lock_irqsave(&ep->lock, flags);

	/* If the file is already "ready" we drop it inside the ready list */
	if ((revents & event->events) && !ep_is_linked(&epi->rdllink)) {
		list_add_tail(&epi->rdllink, &ep->rdllist);

		/* Notify waiting tasks that events are available */
		if (waitqueue_active(&ep->wq))
			wake_up_locked(&ep->wq);
		if (waitqueue_active(&ep->poll_wait))
			pwake++;
	}

	spin_unlock_irqrestore(&ep->lock, flags);

	atomic_inc(&ep->user->epoll_watches);

	
 	/* TODO:  We have to call this outside the lock */
	if (pwake)
		ep_poll_safewake(&ep->poll_wait);

	return 0;


error_unregister:
	ep_unregister_pollwait(ep, epi);

	/*
  	* We need to do this because an event could have been arrived on some
  	* allocated wait queue. Note that we don't care about the ep->ovflist
  	* list, since that is used/cleaned only inside a section bound by "mtx".
  	* And ep_insert() is called with "mtx" held.
  	*/
	spin_lock_irqsave(&ep->lock, flags);
	if (ep_is_linked(&epi->rdllink))
		list_del_init(&epi->rdllink);
	spin_unlock_irqrestore(&ep->lock, flags);

	kmem_cache_free(epi_cache, epi);
	tfile->epoll_item = NULL;

	return error;
}

static int fsocket_ep_remove(struct eventpoll *ep, struct epitem *epi)
{
	unsigned long flags;
	struct file *file = epi->ffd.file;

	DPRINTK(DEBUG, "%s\n", __func__);

	file->epoll_item = NULL;

	ep_unregister_pollwait(ep, epi);

	/* Remove the current item from the list of epoll hooks */
	spin_lock(&file->f_lock);
	if (ep_is_linked(&epi->fllink))
		list_del_init(&epi->fllink);
	spin_unlock(&file->f_lock);

	rb_erase(&epi->rbn, &ep->rbr);

	spin_lock_irqsave(&ep->lock, flags);
	if (ep_is_linked(&epi->rdllink))
		list_del_init(&epi->rdllink);
	spin_unlock_irqrestore(&ep->lock, flags);

	/* At this point it is safe to free the eventpoll item */
	kmem_cache_free(epi_cache, epi);

	atomic_dec(&ep->user->epoll_watches);

	return 0;
}

static int fsocket_ep_modify(struct eventpoll *ep, struct epitem *epi, struct epoll_event *event)
{
	int pwake = 0;
	unsigned int revents;

	DPRINTK(DEBUG, "%s\n", __func__);

	/*
	 * Set the new event interest mask before calling f_op->poll();
	 * otherwise we might miss an event that happens between the
	 * f_op->poll() call and the new event set registering.
	 */
	epi->event.events = event->events;
	epi->event.data = event->data; /* protected by mtx */

	/*
	 * Get current event bits. We can safely use the file* here because
	 * its usage count has been increased by the caller of this function.
	 */
	revents = epi->ffd.file->f_op->poll(epi->ffd.file, NULL);

	/*
	 * If the item is "hot" and it is not registered inside the ready
	 * list, push it inside.
	 */
	if (revents & event->events) {
		spin_lock_irq(&ep->lock);
		if (!ep_is_linked(&epi->rdllink)) {
			list_add_tail(&epi->rdllink, &ep->rdllist);

			/* Notify waiting tasks that events are available */
			if (waitqueue_active(&ep->wq))
				wake_up_locked(&ep->wq);
			if (waitqueue_active(&ep->poll_wait))
				pwake++;
		}
		spin_unlock_irq(&ep->lock);
	}

	/* We have to call this outside the lock */
	if (pwake)
		ep_poll_safewake(&ep->poll_wait);

	return 0;
}

static int fsocket_epoll_ctl(struct eventpoll *ep, struct file *tfile, int fd,  int op,  struct __user epoll_event *ev)
{
	int error = -EINVAL;

	struct epitem *epi;
	struct epoll_event epds;

	struct socket *sock = (struct socket *)tfile->private_data;
	struct file *sfile;

	if (copy_from_user(&epds, ev, sizeof(struct epoll_event)))
		return -EFAULT;

	//FIXME: Do more sanity check.

	mutex_lock(&ep->mtx);
	
	/*
  	 * save epitem object pointer in file struct
  	 */
	if (unlikely(sock->sk->sk_state == TCP_LISTEN))
		epi = ep_find(ep, tfile, fd);
	else
		epi = tfile->epoll_item;

	sfile = tfile->sub_file;

	switch (op) {
	case EPOLL_CTL_ADD:
		if (!epi) {
			epds.events |= POLLERR | POLLHUP;
			error = fsocket_ep_insert(ep, &epds, tfile, fd);
			if (sfile && !error) {
				DPRINTK(DEBUG, "Insert spawned listen socket %d\n", fd);
				error = fsocket_ep_insert(ep, &epds, sfile, fd);
			}
		} else
			error = -EEXIST;
		break;
	case EPOLL_CTL_DEL:
		if (epi)
			error = fsocket_ep_remove(ep, epi);
			if (sfile && !error) {
				DPRINTK(DEBUG, "Remove spawned listen socket %d\n", fd);
				error = fsocket_ep_remove(ep, epi);
			}
		else
			error = -ENOENT;
		break;
	case EPOLL_CTL_MOD:
		if (epi) {
			epds.events |= POLLERR | POLLHUP;
			error = fsocket_ep_modify(ep, epi, &epds);
			if (sfile && !error) {
				DPRINTK(DEBUG, "Modify spawned listen socket %d\n", fd);
				error = fsocket_ep_modify(ep, epi, &epds);
			}
		} else
			error = -ENOENT;
		break;
	}

	mutex_unlock(&ep->mtx);

	return error;
}

cpumask_t cpuset;
static DEFINE_MUTEX(cpumutex);

static int fsocket_process_affinity(struct socket *sock)
{
	int ccpu, ncpu, cpu;
	int tcpu = -1;
	struct cpumask mask;

	mask = current->cpus_allowed;
	ccpu = cpumask_first(&mask);
	ncpu = cpumask_next(ccpu, &mask);

	if (ccpu > (sizeof(sock->sk->cpumask) << 3))
	{
		DPRINTK(ERR, "CPU number exceeds size of cpumask\n");
		return -EPERM;
	}

	if (ccpu >= nr_cpumask_bits) {
		DPRINTK(DEBUG, "Current process affinity is mess\n");
		return -EINVAL;
	}

	if (ncpu >= nr_cpumask_bits) {
		DPRINTK(DEBUG, "Current process already binds to CPU %d\n", ccpu);
		return ccpu;
	}

	if (enable_listen_spawn != ENABLE_LISTEN_SPAWN_AUTOSET_AFFINITY) {
		printk(KERN_ERR "Module para disable autoset affinity for listen-spawn\n");
		return -EPERM;
	}

	mutex_lock(&cpumutex);

	for (cpu = sock->sk->sk_affinity_seq; cpu < num_active_cpus(); 
			cpu = sock->sk->sk_affinity_seq++) {
		if (!cpu_isset(cpu, cpuset)) {
			DPRINTK(DEBUG, "CPU %d is available for process affinity\n", cpu);
			tcpu = cpu;
			break;
		}
	}

	if (tcpu >= 0) {
		cpu_set(cpu, cpuset);
		sock->sk->sk_affinity_seq++;
	}
	else {
		DPRINTK(ERR, "Process number is more than CPU number\n");
		mutex_unlock(&cpumutex);
		return -EINVAL;
	}

	mutex_unlock(&cpumutex);

	cpumask_clear(&current->cpus_allowed);
	cpumask_set_cpu(tcpu, &current->cpus_allowed);

	DPRINTK(DEBUG, "Target socket affinity :%d\n", tcpu);

	return tcpu;
}

static int fsocket_sk_affinity(struct socket *sock, int cpu)
{
	int err = 0;

	sock->sk->cpumask = (unsigned long)1 << cpu;

	DPRINTK(DEBUG, "Bind this listen socket to CPU %d with bitmap 0x%02lx\n", cpu, sock->sk->cpumask);

	return err;
}

static int fsocket_spawn(struct file *filp, int fd, int tcpu)
{
	int ret = 0, nfd, backlog;
	int cpu;
	struct socket *sock, *newsock;
	struct sockaddr_in addr;

	DPRINTK(DEBUG, "Listen spawn listen fd %d on CPU %d\n", fd, tcpu);

	if (!enable_listen_spawn) {
		printk(KERN_ERR "Module para disable listen-spawn feature\n");
		ret = -EPERM;
		goto out;
	}

	sock  = (struct socket *)filp->private_data;
	if (sock == NULL) {
		DPRINTK(ERR, "No socket for this file\n");
		ret = -EBADF;
		goto out;
	}	
	
	ret = fsocket_process_affinity(sock);
	if (ret < 0)
	{
		DPRINTK(ERR, "Set CPU affinity for process failed\n");
		goto out;
	}

	cpu = ret;

	ret = fsocket_spawn_clone(fd, sock, &newsock);
	if (ret < 0) {
		printk(KERN_ERR "New spawn listen socket failed\n");
		goto out;
	}

	ret = fsocket_sk_affinity(newsock, cpu);
	if (ret < 0)
	{
		printk(KERN_ERR "Set CPU affinity for socket %d failed\n", nfd);
		goto release;
	}

	addr.sin_family = AF_INET;
	addr.sin_port = inet_sk(sock->sk)->sport;
	addr.sin_addr.s_addr = inet_sk(sock->sk)->saddr;

	ret = newsock->ops->bind(newsock, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0)
	{
		printk(KERN_ERR "Bind spawned socket %d failed\n", nfd);
		goto release;
	}

	backlog = sock->sk->sk_max_ack_backlog;

	ret = newsock->ops->listen(newsock, backlog);
	if (ret < 0)
	{
		printk(KERN_ERR "Listen spawned socket %d failed\n", nfd);
		goto release;
	}

	ret = fd;

	goto out;

release:
	fsock_release_sock(newsock);
out:
	return ret;
}

static int fastsocket_spawn(struct fsocket_ioctl_arg *u_arg)
{
	struct fsocket_ioctl_arg arg;
	struct file *f = NULL;
	int fd;
	int tcpu;
	int ret = 0;
	int fput_needed;

	if (copy_from_user(&arg, u_arg, sizeof(arg))) {
		DPRINTK(ERR, "copy ioctl parameter from user space to kernel failed\n");
		return -EFAULT;
	}
	
	fd = arg.fd;
	tcpu = arg.op.spawn_op.cpu;

	f = fget_light(fd, &fput_needed);
	if (f == NULL) {
		DPRINTK(ERR, "fd [%d] doesn't exist!\n", fd);
		return -EINVAL;
	}

	DPRINTK(DEBUG, "Listen spawn listen fd %d\n", fd);

	if (f->f_mode & FMODE_FASTSOCKET)
		ret = fsocket_spawn(f, fd, tcpu);
	else {
		DPRINTK(INFO, "Spawn non fastsocket\n");
		return -EINVAL;
	}
	
	fput_light(f, fput_needed);

	return ret;
}

DECLARE_PER_CPU(struct inet_hash_stats, hash_stats);

static inline int fsocket_common_accept(struct socket *sock, struct socket *newsock, int flags)
{
	__get_cpu_var(hash_stats).common_accept++;

	return sock->ops->accept(sock, newsock, flags);
}

static inline int fsocket_local_accept(struct socket *sock, struct socket *newsock, int flags)
{
	__get_cpu_var(hash_stats).local_accept++;

	return sock->ops->accept(sock, newsock, flags);
}

static inline int fsocket_global_accept(struct socket *sock, struct socket *newsock, int flags)
{
	percpu_add(global_spawn_accept, 1);

	if (percpu_read(global_spawn_accept) & 0x1) {
		__get_cpu_var(hash_stats).global_accept++;

		return sock->ops->accept(sock, newsock, flags);
	}

	return -EAGAIN;
}

const struct super_operations *s_op;

static int fsocket_spawn_accept(struct file *file , struct sockaddr __user *upeer_sockaddr, int __user *upeer_addrlen)
{
	int err = 0, newfd, len;

	struct socket *sock, *newsock, *lsock;
	struct sockaddr_storage address;

	struct file *newfile;

	//struct tcp_sock *tp;
	struct inet_connection_sock *icsk;

	sock = (struct socket *)file->private_data;
	if (!sock) {
		printk(KERN_ERR "No socket for file\n");
		err = -EBADF;
		goto out;
	}

	DPRINTK(DEBUG, "Accept file 0x%p\n", file);

	if (!(newsock = fsocket_alloc_socket())) {
		printk(KERN_ERR "Allocate empty socket failed\n");
		err = -ENOMEM;
		goto out;
	}

	newsock->type = SOCK_STREAM;
	newsock->ops = sock->ops;

	//Make it NONBLOCK for Fastsocket
	newfd = fsock_alloc_file(newsock, &newfile, O_NONBLOCK);
	if (unlikely(newfd < 0)) {
		printk(KERN_ERR "Allocate file for new socket failed\n");
		err = newfd;
		fsock_release_sock(newsock);
		goto out;
	}

	if (!file->sub_file) {
		DPRINTK(DEBUG, "File 0x%p has no sub file, Do common accept\n", file);
		err = fsocket_common_accept(sock, newsock, O_NONBLOCK);
	}
	else {

		DPRINTK(DEBUG, "File 0x%p has sub file 0x%p, Do spawn accept\n", file, file->sub_file);
		icsk = inet_csk(sock->sk);
		lsock = (struct socket *)file->sub_file->private_data;
		if (!lsock) {
			printk(KERN_ERR "No socket for sub file\n");
			err = -EBADF;
			goto out_fd;
		}

		if (unlikely(!reqsk_queue_empty(&icsk->icsk_accept_queue))) {
			DPRINTK(DEBUG, "Accept global listen socket 0x%p\n", sock);
			err = fsocket_global_accept(sock, newsock, O_NONBLOCK);
			if (err < 0) {
				DPRINTK(DEBUG, "Check local listen socket 0x%p again\n", lsock);
				err = fsocket_local_accept(lsock, newsock, O_NONBLOCK);
			}
		}
		else {
			DPRINTK(DEBUG, "Accept local listen socket 0x%p\n", lsock);
			err = fsocket_local_accept(lsock, newsock, O_NONBLOCK);
		}
	}

	if (err < 0)
	{	
		//if (err != -EAGAIN)
		//	printk(KERN_ERR "Accept failed [%d]\n", err);
		goto out_fd;
	}

	if (upeer_sockaddr) {
		if (newsock->ops->getname(newsock, (struct sockaddr *)&address, &len, 2) < 0) {
			printk(KERN_ERR "Getname failed for accepted socket\n");
			err = -ECONNABORTED;
			goto out_fd;
		}

		err = move_addr_to_user((struct sockaddr *)&address, len, upeer_sockaddr, upeer_addrlen);

		if (err < 0)
			goto out_fd;
	}

	//sock_set_flag(sock->sk, SOCK_LWS);

	//tp = tcp_sk(sock->sk);
	//TODO: Default TCP OPT For Fastsocket.
	//tp->nonagle |= TCP_NAGLE_OFF | TCP_NAGLE_PUSH;

	fd_install(newfd, newfile);
	err = newfd;

	goto out;

out_fd:
	__fsocket_filp_close(newfile);
	put_unused_fd(newfd);
out:
	return err;
}

int fastsocket_accept(struct fsocket_ioctl_arg *u_arg)
{
	int ret = -1;
	struct fsocket_ioctl_arg arg;
	struct file *tfile = NULL;
	int fput_need;

	if (copy_from_user(&arg, u_arg, sizeof(arg))) {
		DPRINTK(ERR, "copy ioctl parameter from user space to kernel failed\n");
		return -EFAULT;
	}

	tfile =	fget_light(arg.fd, &fput_need);
	if (tfile == NULL) {
		return -ENOENT;
	}

	DPRINTK(DEBUG, "Accept fastsocket %d\n", arg.fd);

	if (tfile->f_mode & FMODE_FASTSOCKET) {
		ret = fsocket_spawn_accept(tfile, arg.op.accept_op.sockaddr, arg.op.accept_op.sockaddr_len);
	}
	else {
		DPRINTK(INFO, "Accept non-fastsocket %d\n", arg.fd);
		ret = sys_accept(arg.fd, arg.op.accept_op.sockaddr, arg.op.accept_op.sockaddr_len);
	}
	fput_light(tfile, fput_need);

	return ret;
}

static int fastsocket_socket(struct fsocket_ioctl_arg *u_arg)
{
	struct fsocket_ioctl_arg arg; 
	int family;
	int type;
	int protocol;

	int fd;

	if (copy_from_user(&arg, u_arg, sizeof(arg))) {
		DPRINTK(ERR, "copy ioctl parameter from user space to kernel failed\n");
		return -EFAULT;
	}

	family = arg.op.socket_op.family;
	type = arg.op.socket_op.type;
	protocol = arg.op.socket_op.protocol;

	DPRINTK(DEBUG,"New fastsocket\n");

	if (( family == AF_INET ) && 
		((type & SOCK_TYPE_MASK) == SOCK_STREAM )) {
		fd = fsocket_socket(type & ~SOCK_TYPE_MASK);
		DPRINTK(DEBUG,"Create fastsocket %d\n", fd);
		return fd;
	}
	else { 
		fd = sys_socket(family, type, protocol);
		DPRINTK(INFO, "Create non fastsocket %d\n", fd);
		return fd;
	}
}

static int fastsocket_close(struct fsocket_ioctl_arg * u_arg)
{
	int error = 0;
	struct file *tfile = NULL;
	struct fsocket_ioctl_arg arg;
	int fput_need;

	if (copy_from_user(&arg, u_arg, sizeof(arg))) {
		DPRINTK(ERR, "copy ioctl parameter from user space to kernel failed\n");
		return -EFAULT;
	}


	tfile = fget_light(arg.fd, &fput_need);

	DPRINTK(DEBUG,"Close fastsocket %d\n", arg.fd);

	if (tfile) {
		if (tfile->f_mode & FMODE_FASTSOCKET) {
			fput_light(tfile, fput_need);
			error = fsocket_close(arg.fd);
		}
		else {
			fput_light(tfile, fput_need);
			DPRINTK(INFO, "Close non fastsocket %d\n", arg.fd);
			error = sys_close(arg.fd);
		}
	} else 
		error = -ENOENT;
	
	return error;
}

static int fastsocket_epoll_ctl(struct fsocket_ioctl_arg *u_arg)
{
	struct fsocket_ioctl_arg arg;

	struct file *ep_file, *tfile;
	struct eventpoll *ep;
	int fput_need, fput_need1, ret;

	if (copy_from_user(&arg, u_arg, sizeof(arg))) {
		DPRINTK(ERR, "copy ioctl parameter from user space to kernel failed\n");
		return -EFAULT;
	}
	
	ep_file = fget_light(arg.op.epoll_op.epoll_fd, &fput_need);
	if (ep_file == NULL) {
		DPRINTK(ERR, "epoll file don't exist!\n");
		return -EINVAL;
	}

	ep = (struct eventpoll *)ep_file->private_data;
	
	tfile = fget_light(arg.fd, &fput_need1);
	if (tfile == NULL) {
		fput_light(ep_file, fput_need);
		DPRINTK(ERR, "target file don't exist!\n");
		return -EINVAL;
	}

	DPRINTK(DEBUG, "Epoll_ctl socket %d\n", arg.fd);

	if (tfile->f_mode & FMODE_FASTSOCKET) {
		ret = fsocket_epoll_ctl(ep, tfile, arg.fd, arg.op.epoll_op.ep_ctl_cmd, arg.op.epoll_op.ev);

	} else {
		DPRINTK(INFO, "Target socket %d is Not Fastsocket\n", arg.fd);
		ret = sys_epoll_ctl(arg.op.epoll_op.epoll_fd, arg.op.epoll_op.ep_ctl_cmd, 
					arg.fd, arg.op.epoll_op.ev);
	}

	fput_light(tfile, fput_need1);
	fput_light(ep_file, fput_need);

	return ret;
}

/*

static int recv_tcp_actor(read_descriptor_t * desc, struct sk_buff *skb, 
		unsigned int offset, size_t len)
{
	struct read_sock_arg *arg = desc->arg.data;
	struct iovec iov;
	int copylen;
	int ret;

	iov.iov_base = arg->buf + desc->written;
	iov.iov_len = arg->size - desc->written;

	copylen = min(iov.iov_len, len);
	if (copylen <= 0)
		return 0;

	ret = skb_copy_datagram_iovec(skb, offset, &iov, copylen);
	if (ret < 0)
		return ret;

	desc->written += copylen;

	return copylen;
}

static int fsocket_read(struct socket *sock, char __user *buf, int len) 
{
	int ret = 0;
	struct sock *sk = sock->sk;
	struct read_sock_arg read_arg;
	read_descriptor_t desc;

	DPRINTK(DEBUG, "%s:len=%d\n", __func__,len);

	read_arg.buf = buf;
	read_arg.size = len;

	desc.written = 0;
	desc.count = 1;
	desc.arg.data = &read_arg;

	lock_sock(sk);
	ret = tcp_read_sock(sk, &desc, recv_tcp_actor);
	release_sock(sk);

	return ret;
}

static int fastsocket_read(struct fsocket_ioctl_arg * u_arg)
{
	struct fsocket_ioctl_arg arg; 
	struct file *tfile = NULL;
	int ret = -1, fput_need;

	if (copy_from_user(&arg, u_arg, sizeof(arg))) {
		DPRINTK(ERR, "copy ioctl parameter from user space to kernel failed\n");
		return -EFAULT;
	}
		
	tfile =	fget_light(arg.fd, &fput_need);
	if (tfile == NULL) {
		return -ENOENT;
	}

	if (tfile->f_mode & FMODE_FASTSOCKET) 
		ret = fsocket_read(tfile->private_data, arg.op.io_op.buf, arg.op.io_op.buf_len);
	else {
		DPRINTK(INFO, "Read normal socket %d\n", arg.fd);
		ret = sys_read(arg.fd, arg.op.io_op.buf, arg.op.io_op.buf_len);
	}

	fput_light(tfile, fput_need);
	return ret;
}

static int fsocket_write(struct socket *sock, char __user *buf, int len)
{
	int ret = 0;
	struct iovec iov;
	struct msghdr msg;

	DPRINTK(DEBUG, "%s: len=%d\n", __func__, len);

	iov.iov_base = buf;
	iov.iov_len = len;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_flags = MSG_DONTWAIT;

	ret = tcp_sendmsg(NULL, sock, &msg, len);
	
	return ret;
}

static int fastsocket_write(struct fsocket_ioctl_arg * u_arg)
{
	struct fsocket_ioctl_arg arg; 
	struct file *tfile = NULL;
	int ret = -1, fput_need;

	if (copy_from_user(&arg, u_arg, sizeof(arg))) {
		DPRINTK(ERR, "copy ioctl parameter from user space to kernel failed\n");
		return -EFAULT;
	}
		
	tfile =	fget_light(arg.fd, &fput_need);
	if (tfile == NULL) {
		return -ENOENT;
	}

	if (tfile->f_mode & FMODE_FASTSOCKET) 
		ret = fsocket_write(tfile->private_data, arg.op.io_op.buf, arg.op.io_op.buf_len);
	else {
		DPRINTK(INFO, "Write normal socket %d\n", arg.fd);
		ret = sys_write(arg.fd, arg.op.io_op.buf, arg.op.io_op.buf_len);
	}

	fput_light(tfile,fput_need);
	return ret;

}

*/

static long fastsocket_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case FSOCKET_IOC_SOCKET:
		return fastsocket_socket((struct fsocket_ioctl_arg *) arg);
	case FSOCKET_IOC_SPAWN:
		return fastsocket_spawn((struct fsocket_ioctl_arg *) arg);
	case FSOCKET_IOC_ACCEPT:
		return fastsocket_accept((struct fsocket_ioctl_arg *)arg);
	//case FSOCKET_IOC_READ:
	//	return fastsocket_read((struct fsocket_ioctl_arg *)arg);
	//case FSOCKET_IOC_WRITE:
	//	return fastsocket_write((struct fsocket_ioctl_arg *)arg);
	case FSOCKET_IOC_CLOSE:
		return fastsocket_close((struct fsocket_ioctl_arg *) arg);
	case FSOCKET_IOC_EPOLL_CTL:
		return fastsocket_epoll_ctl((struct fsocket_ioctl_arg *)arg);
	default:
		DPRINTK(WARNING, "ioctl [%d] operation not support\n", cmd);
		break;
	}
	return -EINVAL;
}

static int fsocket_open(struct inode *inode, struct file *filp)
{
	if (!try_module_get(THIS_MODULE)) {
		DPRINTK(ERR, "Add reference to fastsocket module failed\n");
		return -EINVAL;
	}

	DPRINTK(INFO, "Hold module reference\n");

	filp->private_data = (void *)THIS_MODULE;

	cpus_clear(cpuset);

	return 0;
}

static int fsocket_release(struct inode *inode, struct file *filp)
{
	module_put(filp->private_data);
	
	DPRINTK(INFO, "Release module reference\n");

	return 0;
}

static const struct file_operations fastsocket_fops = {
	.open = fsocket_open,
	.release = fsocket_release,
	.unlocked_ioctl = fastsocket_ioctl,
};

static struct miscdevice fastsocket_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "fastsocket_channel",
	.fops = &fastsocket_fops ,
	.mode = S_IRUGO,
};

static void init_once(void *foo)
{
	struct socket_alloc *ei = (struct socket_alloc *)foo;

	inode_init_once(&ei->vfs_inode);
}

static int __init  fastsocket_init(void)
{
	int ret = 0;

	DPRINTK(INFO, "CPU number: online %d possible %d present %d active %d\n",
			num_online_cpus(), num_possible_cpus(),
			num_present_cpus(), num_active_cpus());
	
	ret = misc_register(&fastsocket_dev);
	if (ret < 0) {
		DPRINTK(ERR, "Register fastsocket channel device failed\n");
		return -ENOMEM;
	}

	socket_cachep = kmem_cache_create("fastsocket_socket_cache", sizeof(struct fsocket_alloc), 0, 
			SLAB_HWCACHE_ALIGN | SLAB_RECLAIM_ACCOUNT | SLAB_PANIC, init_once);

	ret = register_filesystem(&fastsock_fs_type);
	if (ret) {
		misc_deregister(&fastsocket_dev);
		DPRINTK(ERR, "Register fastsocket filesystem failed\n");
		return ret;
	}

	sock_mnt = kern_mount(&fastsock_fs_type);
	DPRINTK(DEBUG, "Fastsocket super block 0x%p ops 0x%p\n", sock_mnt->mnt_sb, sock_mnt->mnt_sb->s_op);

	s_op = sock_mnt->mnt_sb->s_op;

	if (IS_ERR(sock_mnt)) {
		DPRINTK(ERR, "Mount fastsocket filesystem failed\n");
		ret = PTR_ERR(sock_mnt);
		misc_deregister(&fastsocket_dev);
		unregister_filesystem(&fastsock_fs_type);
		return ret;
	}

	printk(KERN_INFO "Load Fastsocket Module\n");

	return ret;
}

static void __exit fastsocket_exit(void)
{
	misc_deregister(&fastsocket_dev);

	DPRINTK(DEBUG, "Fastsocket super block 0x%p ops 0x%p\n", sock_mnt->mnt_sb, sock_mnt->mnt_sb->s_op);
	mntput(sock_mnt);
	unregister_filesystem(&fastsock_fs_type);

	kmem_cache_destroy(socket_cachep);

	printk(KERN_INFO "Remove Fastsocket Module\n");
}

module_init(fastsocket_init)
module_exit(fastsocket_exit)

