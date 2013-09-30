#include <sys/inotify.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/inotify.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#include <common/cfgparse.h>
#include <common/memory.h>
#include <common/time.h>
#include <types/proxy.h>
#include <types/global.h>
#include <proto/inotify.h>
#include <proto/log.h>
#include <proto/proxy.h>
#include <proto/fd.h>
#include <proto/task.h>
#include <proto/checks.h>
#include <common/errors.h>

extern struct global global;

#define PROXY_INOTIFY_EVENT_TRIGGERED 0x01

int acl_load_rule(struct proxy *px, int reload);

/*
 * process_acl_inotify_event
 * iterator the proxy list, find some proxy have acl_file change
 * than process it
 */
void   
process_acl_inotify_event (struct proxy *px, int fd) 
{		
	int err_code;

	err_code = acl_load_rule(px, ACL_RELOAD);
	if (err_code&ERR_ABORT || err_code&ERR_FATAL){
		Alert ("the new acl: %s  can't loaded\n", px->conf.acl_file);
		goto out;
	}

out:
	return;
}
/*
 * monitor file modify event, reload server config automaticly
 */
int process_inotify(int fd)
{
	int nread = 0;
	struct proxy *px = proxy;
	struct inotify_event file_ev;

	errno = 0;
	while(1) {
		nread = read(fd, &file_ev, sizeof (struct inotify_event));
		if (nread == sizeof(struct inotify_event)) {
			if (!(file_ev.mask & (IN_DELETE | IN_DELETE_SELF | IN_MODIFY))) {
				Alert ("ERROR:Received an unregistered event: %x\n", file_ev.mask);
				continue;
			}
			
			//find the proxy of inotified
			px = proxy;
			while (px) {
				if (px->conf.inotify_fd == file_ev.wd)
					break;
				px = px->next;
			}

			if(px) {
				px->conf.flags |= PROXY_INOTIFY_EVENT_TRIGGERED;
			} else {
				Alert ("ERROR:while received an inotify event,"
						"but can't find corresponse proxy\n");
			}
			
		} else {
			send_log(px, LOG_WARNING, "Read inotify event error,nread=%d,error=%s\n", 
					nread, strerror(errno));
			break;
		}
	}
	
	for (px = proxy; px != NULL; px= px->next)
	{
		if((px->conf.flags & PROXY_INOTIFY_EVENT_TRIGGERED) == 0) 
			continue;

		memset(trash, 0, sizeof(trash));
		if ((px->cap & PR_CAP_FE) &&
			(px->conf.inotify_fd > 0) && 
			(px->options3 & PR_O3_ACL_FROM_FILE)) {
			process_acl_inotify_event (px, fd);
			snprintf(trash, sizeof(trash), 
					BACKEND_FILE_PATH"%s", px->conf.acl_file);
		} else if((px->cap & PR_CAP_BE) && 
				 (px->conf.inotify_fd > 0) && 
				 (px->options3 & PR_O3_SERVER_FROM_FILE)) {
			reload_backend_server(px);
			snprintf(trash, sizeof(trash), 
					BACKEND_FILE_PATH"%s", px->conf.backend_server_file);
		}
		px->conf.flags &= ~PROXY_INOTIFY_EVENT_TRIGGERED;

		//re-register the file notify
		inotify_rm_watch(fd, px->conf.inotify_fd);
		px->conf.inotify_fd = inotify_add_watch(fd, trash, 
						IN_DELETE | IN_DELETE_SELF | IN_MODIFY);
		if(px->conf.inotify_fd < 0) {
			send_log(px, LOG_WARNING, "[%d]Re-add inotify failed,file=%s,error=%s",
					(int)now.tv_sec, trash, strerror(errno));
		}
	}
	
	return 0;
}


static void free_server(struct server *srv)
{
	if (srv->check_data) {
		free(srv->check_data);
		srv->check_data = NULL;
	}

	if(srv->cookie) {
		free(srv->cookie);
		srv->cookie = NULL;
	}
	if(srv->id) {
		free(srv->id);
		srv->id = NULL;
	}
	pool_free2(pool2_server,srv);

	return;		
}

int reload_backend_server(struct proxy *px)
{
	struct server *srv = NULL;
	struct server *tmp = NULL;

	//check server file is empty before set server down.
	{
		struct stat f_stat;
		memset(trash, 0, sizeof(trash));
		snprintf(trash, sizeof(trash)/sizeof(trash[0]) - 1, BACKEND_FILE_PATH"%s", 
			px->conf.backend_server_file);

		memset(&f_stat, 0, sizeof(f_stat));
		//1.1.1.1,1,1,3,1,3 == 17 bytes
		if (stat(trash,&f_stat) ||
			(f_stat.st_size < 17)) {
			send_log(px, LOG_WARNING, "[%d]server file %s is empty\n", 
					(int)now.tv_sec, px->conf.backend_server_file);
			return 0;
		}
	}

	send_log(px, LOG_WARNING, "[%d]reload proxy %s's server list\n", 
			(int)now.tv_sec, px->conf.backend_server_file);

	/*delete servers in unused server list which has no active session*/
	srv =  px->unused_srv;
	while(srv != NULL) {
		if (srv->cur_sess == 0) {
			tmp = srv;
			srv = srv->next;

			free_server(tmp);
			continue;
		}
		break;
	}
	px->unused_srv = srv;

#if 0
	pre_srv = srv;
	srv = (srv != NULL)?srv->next:NULL;

	while(srv != NULL) {
		if(srv->cur_sess == 0) {
			tmp = srv;
			pre_srv->next = srv->next;
			srv = srv->next;

			free_server(tmp);
		}
		else {
			pre_srv = srv;
			srv = srv->next;
		}
	}
#endif
	/*stop health check firstly,then move current server list to unused server list */
	srv = px->srv;
	while(srv != NULL) {
		tmp = srv;

		srv->state |= SRV_MAINTAIN;
		set_server_down(srv);

		//stop check daemon
		if(srv->curfd != -1)
		{
			fd_delete(srv->curfd);
			srv->curfd = -1;
		}

		if (srv->warmup) {
			task_delete(srv->warmup);
			task_free(srv->warmup);
		}

		if (srv->check) {
			task_delete(srv->check);
			task_free(srv->check);
		}

		/*delete server id from id tree */
		eb32_delete(&srv->conf.id);

		if (srv->cur_sess == 0) {
			srv = srv->next;
			free_server(tmp);
			continue;
		}
		srv = srv->next;

		/*add to unused srv list*/
		tmp->next = px->unused_srv;
		px->unused_srv = tmp;
	}

	px->srv = NULL;
	px->conf.used_server_id = EB_ROOT;
	if (px->conf.backend_server_file)
		read_server_file(px);

	/*reinit lb algorithm*/
	if(px->lbprm.reinit)
		px->lbprm.reinit(px);

	start_check(px);
	return 0;
}

int init_inotify_instance(void) 
{
	int fd = global.inotify_fd = inotify_init();
	if (-1 == global.inotify_fd) {
		Alert("[%s:%d] Init inotify instance failed, error=%s\n", __FILE__, __LINE__, strerror(errno));
		return -1;
	}
	else {
		if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
			Alert("can't make inotify non-blocking\n");
		}
	}

	fd_insert(global.inotify_fd);
	fdtab[global.inotify_fd].cb[DIR_RD].f = process_inotify;
	fdtab[global.inotify_fd].cb[DIR_WR].f = NULL; /* never called */
	fdtab[global.inotify_fd].cb[DIR_RD].b = fdtab[global.inotify_fd].cb[DIR_WR].b = NULL;
	fdtab[global.inotify_fd].owner = &global; /* reference the listener instead of a task */
	fdtab[global.inotify_fd].state = FD_STLISTEN;
	fdinfo[global.inotify_fd].peeraddr = NULL;
	fdinfo[global.inotify_fd].peerlen = 0;

	return 0;
}

int install_inotify_watch(struct proxy *po)
{
	/*
	 * install inotify watch
	 */
	struct proxy *px = NULL;

	for( px = po; px != NULL; px = px->next) {

		if (( px->cap & PR_CAP_BE ) && ( px->options3 & PR_O3_SERVER_FROM_FILE )) {
			memset(trash, 0, sizeof(trash));
			snprintf(trash, sizeof(trash)/sizeof(char) - 1, BACKEND_FILE_PATH"%s", px->conf.backend_server_file);
			px->conf.inotify_fd = inotify_add_watch(global.inotify_fd, trash, 
					IN_DELETE | IN_DELETE_SELF | IN_MODIFY);
			if(px->conf.inotify_fd < 0) {
				send_log(px, LOG_WARNING, "[%d]Re-add inotify failed,file=%s,error=%s",(int)now.tv_sec,
						px->conf.backend_server_file, strerror(errno));
			}

		}

		if (( px->cap & PR_CAP_FE ) && ( px->options3 & PR_O3_ACL_FROM_FILE )) {
			memset(trash, 0, sizeof(trash));
			snprintf(trash, sizeof(trash)/sizeof(char) - 1, BACKEND_FILE_PATH"%s", 
					px->conf.acl_file);
			px->conf.inotify_fd = inotify_add_watch(global.inotify_fd, trash, 
					IN_DELETE | IN_DELETE_SELF | IN_MODIFY);
			if(px->conf.inotify_fd < 0) {
				send_log(px, LOG_WARNING, "[%d]Re-add inotify failed,file=%s,error=%s",(int)now.tv_sec,
						px->conf.acl_file, strerror(errno));
			}
		}
	}
	return 0;
}
