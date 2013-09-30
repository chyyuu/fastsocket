#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/resource.h>
#include <time.h>
#include <syslog.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/prctl.h>

#ifdef DEBUG_FULL
#include <assert.h>
#endif

#include <common/appsession.h>
#include <common/base64.h>
#include <common/cfgparse.h>
#include <common/compat.h>
#include <common/config.h>
#include <common/defaults.h>
#include <common/errors.h>
#include <common/memory.h>
#include <common/mini-clist.h>
#include <common/regex.h>
#include <common/standard.h>
#include <common/time.h>
#include <common/uri_auth.h>
#include <common/version.h>

#include <types/capture.h>
#include <types/global.h>

#include <proto/auth.h>
#include <proto/acl.h>
#include <proto/backend.h>
#include <proto/buffers.h>
#include <proto/checks.h>
#include <proto/client.h>
#include <proto/fd.h>
#include <proto/log.h>
#include <proto/protocols.h>
#include <proto/proto_http.h>
#include <proto/proxy.h>
#include <proto/queue.h>
#include <proto/server.h>
#include <proto/session.h>
#include <proto/signal.h>
#include <proto/stream_sock.h>
#include <proto/task.h>
#include <proto/inotify.h>
#include <proto/server.h>
#include <types/proto_tcp.h>

#ifdef CONFIG_HAP_CTTPROXY
#include <proto/cttproxy.h>
#endif

// for compile
/* list of config files */
static struct list cfg_cfgfiles = LIST_HEAD_INIT(cfg_cfgfiles);
int  pid;			/* current process id */
int  relative_pid = 1;		/* process id starting at 1 */
long cpu_frequency = 0;

char acl_sequence[ACL_MAX_SEQUENCE_LEN];    /* record the acl(7layer) configuration's sequence */

/* global options */
struct global global = {
	logfac1 : -1,
	logfac2 : -1,
	loglev1 : 7, /* max syslog level : debug */
	loglev2 : 7,
	.stats_sock = {
		.maxconn = 10, /* 10 concurrent stats connections */
		.perm = {
			 .ux = {
				 .uid = -1,
				 .gid = -1,
				 .mode = 0,
			 }
		 }
	},
	.tune = {
		.bufsize = BUFSIZE,
		.maxrewrite = MAXREWRITE,
		.chksize = BUFSIZE,
	},
	.inotify_fd = -1,
	.rlimit_core = 0,
	/* others NULL OK */
};

/*********************************************************************/

int stopping;	/* non zero means stopping in progress */
int shut_down_now; /* too long elapsed from recived stop signal, shutdown now.*/
struct timeval tv_stop; /* shut down time. */

/* Here we store informations about the pids of the processes we may pause
 * or kill. We will send them a signal every 10 ms until we can bind to all
 * our ports. With 200 retries, that's about 2 seconds.
 */
#define MAX_START_RETRIES	200
static int *oldpids = NULL;
static int oldpids_sig; /* use USR1 or TERM */

/* this is used to drain data, and as a temporary buffer for sprintf()... */
char trash[BUFSIZE];

/* this buffer is always the same size as standard buffers and is used for
 * swapping data inside a buffer.
 */
char *swap_buffer = NULL;

int nb_oldpids = 0;
const int zero = 0;
const int one = 1;
const struct linger nolinger = { .l_onoff = 1, .l_linger = 0 };

char lb_name[((MAX_HOSTNAME_LEN + 2)/3) * 4 + 1] = "";
char hostname[MAX_HOSTNAME_LEN];


int acl_load_rule(struct proxy *px, int reload);

//nima, static function !!!
static void init_new_proxy(struct proxy *p)
{
	memset(p, 0, sizeof(struct proxy));
	LIST_INIT(&p->pendconns);
	LIST_INIT(&p->acl);
	LIST_INIT(&p->req_acl);
	LIST_INIT(&p->block_cond);
	LIST_INIT(&p->redirect_rules);
	LIST_INIT(&p->mon_fail_cond);
	LIST_INIT(&p->switching_rules);
	LIST_INIT(&p->persist_rules);
	LIST_INIT(&p->sticking_rules);
	LIST_INIT(&p->storersp_rules);
	LIST_INIT(&p->tcp_req.inspect_rules);
	LIST_INIT(&p->req_add);
	LIST_INIT(&p->rsp_add);
	p->hdrname2xforward = NULL;

	p->timeout.client = TICK_ETERNITY;
	p->timeout.tarpit = TICK_ETERNITY;
	p->timeout.queue = TICK_ETERNITY;
	p->timeout.connect = TICK_ETERNITY;
	p->timeout.server = TICK_ETERNITY;
	p->timeout.appsession = TICK_ETERNITY;
	p->timeout.httpreq = TICK_ETERNITY;
	p->cap |= PR_CAP_FE|PR_CAP_RS;
}

int main(int argc, char* argv[])
{
	struct proxy px_test;

	if (argc != 2 ) {
		printf ("Usage: %s file \n", argv[0]);
		return -1;
	}

/*
	memset(trash, 0, sizeof(trash));
	snprintf(trash, sizeof(trash)/sizeof(trash[0]) - 1, "%s/%s", 
			BACKEND_FILE_PATH, px->conf.acl_file);
	*/

	init_new_proxy (&px_test);
	px_test.conf.acl_file =strdup(argv[1]); 

	if (acl_load_rule(&px_test, ACL_INIT) != ERR_NONE) {
		printf ("ERROR\n");
		return -1;
		}

	printf ("SUCCESS\n");
	return 0;
}
