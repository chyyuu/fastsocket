/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Generic INET transport hashtables
 *
 * Authors:	Lotsa people, from code originally in tcp
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#include <linux/module.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/cpu.h>
#include <net/inet_connection_sock.h>
#include <net/inet_hashtables.h>
#include <net/secure_seq.h>
#include <net/ip.h>

#include <linux/log2.h>

//#define DPRINTK(klevel, fmt, args...) printk(KERN_##klevel "[Hydra Channel]" " [CPU%d] %s:%d\t" fmt, smp_processor_id(), __FUNCTION__ , __LINE__, ## args)
#define DPRINTK(klevel, fmt, args...)

//XIAOFENG6
DEFINE_PER_CPU(struct inet_hash_stats, hash_stats);
EXPORT_PER_CPU_SYMBOL(hash_stats);
//XIAOFENG6

/*
 * Allocate and initialize a new local port bind bucket.
 * The bindhash mutex for snum's hash chain must be held here.
 */
struct inet_bind_bucket *inet_bind_bucket_create(struct kmem_cache *cachep,
						 struct net *net,
						 struct inet_bind_hashbucket *head,
						 const unsigned short snum)
{
	struct inet_bind_bucket *tb = kmem_cache_alloc(cachep, GFP_ATOMIC);

	if (tb != NULL) {
		write_pnet(&tb->ib_net, hold_net(net));
		tb->port      = snum;
		tb->fastreuse = 0;
		tb->num_owners = 0;
		INIT_HLIST_HEAD(&tb->owners);
		hlist_add_head(&tb->node, &head->chain);
	}
	return tb;
}

/*
 * Caller must hold hashbucket lock for this tb with local BH disabled
 */
void inet_bind_bucket_destroy(struct kmem_cache *cachep, struct inet_bind_bucket *tb)
{
	if (hlist_empty(&tb->owners)) {
		__hlist_del(&tb->node);
		release_net(ib_net(tb));
		kmem_cache_free(cachep, tb);
	}
}

void inet_bind_hash(struct sock *sk, struct inet_bind_bucket *tb,
		    const unsigned short snum)
{
	struct inet_hashinfo *hashinfo = sk->sk_prot->h.hashinfo;

	atomic_inc(&hashinfo->bsockets);

	inet_sk(sk)->num = snum;
	sk_add_bind_node(sk, &tb->owners);
	tb->num_owners++;
	inet_csk(sk)->icsk_bind_hash = tb;
}

/*
 * Get rid of any references to a local port held by the given sock.
 */
static void __inet_put_port(struct sock *sk)
{
	struct inet_hashinfo *hashinfo = sk->sk_prot->h.hashinfo;
	const int bhash = inet_bhashfn(sock_net(sk), inet_sk(sk)->num,
			hashinfo->bhash_size);
	struct inet_bind_hashbucket *head = &hashinfo->bhash[bhash];
	struct inet_bind_bucket *tb;

	atomic_dec(&hashinfo->bsockets);

	spin_lock(&head->lock);
	tb = inet_csk(sk)->icsk_bind_hash;
	__sk_del_bind_node(sk);
	tb->num_owners--;
	inet_csk(sk)->icsk_bind_hash = NULL;
	inet_sk(sk)->num = 0;
	inet_bind_bucket_destroy(hashinfo->bind_bucket_cachep, tb);
	spin_unlock(&head->lock);
}

void inet_put_port(struct sock *sk)
{
	local_bh_disable();
	__inet_put_port(sk);
	local_bh_enable();
}

EXPORT_SYMBOL(inet_put_port);

int __inet_inherit_port(struct sock *sk, struct sock *child)
{
	struct inet_hashinfo *table = sk->sk_prot->h.hashinfo;
	unsigned short port = inet_sk(child)->num;
	const int bhash = inet_bhashfn(sock_net(sk), port,
			table->bhash_size);
	struct inet_bind_hashbucket *head = &table->bhash[bhash];
	struct inet_bind_bucket *tb;

	spin_lock(&head->lock);
	tb = inet_csk(sk)->icsk_bind_hash;
	if (tb->port != port) {
		/* NOTE: using tproxy and redirecting skbs to a proxy
		 * on a different listener port breaks the assumption
		 * that the listener socket's icsk_bind_hash is the same
		 * as that of the child socket. We have to look up or
		 * create a new bind bucket for the child here. */
		struct hlist_node *node;
		inet_bind_bucket_for_each(tb, node, &head->chain) {
			if (net_eq(ib_net(tb), sock_net(sk)) &&
			    tb->port == port)
				break;
		}
		if (!node) {
			tb = inet_bind_bucket_create(table->bind_bucket_cachep,
						     sock_net(sk), head, port);
			if (!tb) {
				spin_unlock(&head->lock);
				return -ENOMEM;
			}
		}
	}
	sk_add_bind_node(child, &tb->owners);
	inet_csk(child)->icsk_bind_hash = tb;
	spin_unlock(&head->lock);

	return 0;
}

EXPORT_SYMBOL_GPL(__inet_inherit_port);

static inline int compute_score(struct sock *sk, struct net *net,
				const unsigned short hnum, const __be32 daddr,
				const int dif)
{
	int score = -1;
	struct inet_sock *inet = inet_sk(sk);

	//XIAOFENG6
	int processor_id = smp_processor_id();
	//XIAOFENG6

	if (net_eq(sock_net(sk), net) && inet->num == hnum &&
			!ipv6_only_sock(sk)) {
		__be32 rcv_saddr = inet->rcv_saddr;
		score = sk->sk_family == PF_INET ? 1 : 0;
		if (rcv_saddr) {
			if (rcv_saddr != daddr)
				return -1;
			score += 2;
		}
		if (sk->sk_bound_dev_if) {
			if (sk->sk_bound_dev_if != dif)
				return -1;
			score += 2;
		}

		//XIAOFENG6
		if (sk->cpumask == 0)
			score++;

		//FIXME: Each Socket should bound to one single CPU
		if (sk->cpumask & ((unsigned long)1 << processor_id))
			score += 2;
		//XIAOFENG6
	}
	return score;
}

static struct sock * __inet_lookup_local_listener(struct net *net, 
					   struct inet_hashinfo *hashinfo,
					   const __be32 daddr, const unsigned short hum,
					   const int dif)
{
	int score = 0, hiscore = 0;
	struct sock *sk, *result;
	struct hlist_nulls_node *node;
	unsigned int hash = inet_lhashfn_ex(net, daddr, hum);
	struct inet_listen_hash_chunk *lis_chunk = per_cpu_ptr(hashinfo->local_listening_hash, smp_processor_id());
	struct inet_listen_hashbucket *ilb = &lis_chunk->listening_hash[hash];
	
	result = NULL;
	hiscore = -1;

begin:	
	//sk_nulls_for_each_rcu(sk, node, &ilb->head) {
	sk_nulls_for_each(sk, node, &ilb->head) {
		score = compute_score(sk, net, hum, daddr, dif);
		if (score > hiscore) {
			result = sk;
			hiscore = score;
		}
	}

	/*
	 * if the nulls value we got at the end of this lookup is
	 * not the expected one, we must restart lookup.
	 * We probably met an item that was moved to another chain.
	 */
	if (get_nulls_value(node) != hash + LISTENING_NULLS_BASE)
		goto begin;
	if (result) {
		if (unlikely(!atomic_inc_not_zero(&result->sk_refcnt)))
			result = NULL;
		else if (unlikely(compute_score(result, net, hum, daddr,
				  dif) < hiscore)) {
			sock_put(result);
			goto begin;
		}
	} else {
		hash = inet_lhashfn_ex(net, 0, hum);
		ilb = &lis_chunk->listening_hash[hash];
begin1:
		result = NULL;
		hiscore = -1;
		
		//sk_nulls_for_each_rcu(sk, node, &ilb->head) {
		sk_nulls_for_each(sk, node, &ilb->head) {
			score = compute_score(sk, net, hum, daddr, dif);
			if (score > hiscore) {
				result = sk;
				hiscore = score;
			}
		}
		if (get_nulls_value(node) != hash + LISTENING_NULLS_BASE)
			goto begin1;

		if (result) {
			if (unlikely(!atomic_inc_not_zero(&result->sk_refcnt)))
				result = NULL;
			else if (unlikely(compute_score(result, net, hum, daddr,
					  dif) < hiscore)) {
				sock_put(result);
				goto begin1;
			}
		}
	}

	//XIAOFENG6
	if (result)
		__get_cpu_var(hash_stats).local_listen_lookup++;
	//XIAOFENG6

	return result;
}


/*
 * Don't inline this cruft. Here are some nice properties to exploit here. The
 * BSD API does not allow a listening sock to specify the remote port nor the
 * remote address for the connection. So always assume those are both
 * wildcarded during the search since they can never be otherwise.
 */


struct sock *__inet_lookup_listener(struct net *net,
				    struct inet_hashinfo *hashinfo,
				    const __be32 daddr, const unsigned short hnum,
				    const int dif)
{
	struct sock *sk, *result;
	struct hlist_nulls_node *node;
	unsigned int hash = inet_lhashfn_ex(net, daddr, hnum);
	struct inet_listen_hashbucket *ilb = &hashinfo->listening_hash[hash];
	int score, hiscore;

	
	result = __inet_lookup_local_listener(net, hashinfo, daddr, hnum, dif);
	if (result) {
		return result;
	}

	rcu_read_lock();
begin:
	result = NULL;
	hiscore = -1;
	sk_nulls_for_each_rcu(sk, node, &ilb->head) {
		score = compute_score(sk, net, hnum, daddr, dif);
		if (score > hiscore) {
			result = sk;
			hiscore = score;
		}
	}
	/*
	 * if the nulls value we got at the end of this lookup is
	 * not the expected one, we must restart lookup.
	 * We probably met an item that was moved to another chain.
	 */
	if (get_nulls_value(node) != hash + LISTENING_NULLS_BASE)
		goto begin;
	if (result) {
		if (unlikely(!atomic_inc_not_zero(&result->sk_refcnt)))
			result = NULL;
		else if (unlikely(compute_score(result, net, hnum, daddr,
				  dif) < hiscore)) {
			sock_put(result);
			goto begin;
		}
	} else {
		
		hash = inet_lhashfn_ex(net, 0, hnum);
		ilb = &hashinfo->listening_hash[hash];
begin1:
		result = NULL;
		hiscore = -1;
		
		sk_nulls_for_each_rcu(sk, node, &ilb->head) {
			score = compute_score(sk, net, hnum, daddr, dif);
			if (score > hiscore) {
				result = sk;
				hiscore = score;
			}
		}
		if (get_nulls_value(node) != hash + LISTENING_NULLS_BASE)
			goto begin1;

		if (result) {
			if (unlikely(!atomic_inc_not_zero(&result->sk_refcnt)))
				result = NULL;
			else if (unlikely(compute_score(result, net, hnum, daddr,
					  dif) < hiscore)) {
				sock_put(result);
				goto begin1;
			}
		}
	}
	rcu_read_unlock();

	//XIAOFENG6
	if (result)
		__get_cpu_var(hash_stats).global_listen_lookup++;
	//XIAOFENG6
	return result;
}
EXPORT_SYMBOL_GPL(__inet_lookup_listener);

struct sock * __inet_lookup_established(struct net *net,
				  struct inet_hashinfo *hashinfo,
				  const __be32 saddr, const __be16 sport,
				  const __be32 daddr, const u16 hnum,
				  const int dif)
{
	INET_ADDR_COOKIE(acookie, saddr, daddr)
	const __portpair ports = INET_COMBINED_PORTS(sport, hnum);
	struct sock *sk;
	const struct hlist_nulls_node *node;
	/* Optimize here for direct hit, only listening connections can
	 * have wildcards anyways.
	 */
	unsigned int hash = inet_ehashfn(net, daddr, hnum, saddr, sport);
	unsigned int slot = hash & (hashinfo->ehash_size - 1);
	struct inet_ehash_bucket *head = &hashinfo->ehash[slot];

	rcu_read_lock();
begin:
	sk_nulls_for_each_rcu(sk, node, &head->chain) {
		if (INET_MATCH(sk, net, hash, acookie,
					saddr, daddr, ports, dif)) {
			if (unlikely(!atomic_inc_not_zero(&sk->sk_refcnt)))
				goto begintw;
			if (unlikely(!INET_MATCH(sk, net, hash, acookie,
				saddr, daddr, ports, dif))) {
				sock_put(sk);
				goto begin;
			}
			goto out;
		}
	}
	/*
	 * if the nulls value we got at the end of this lookup is
	 * not the expected one, we must restart lookup.
	 * We probably met an item that was moved to another chain.
	 */
	if (get_nulls_value(node) != slot)
		goto begin;

begintw:
	/* Must check for a TIME_WAIT'er before going to listener hash. */
	sk_nulls_for_each_rcu(sk, node, &head->twchain) {
		if (INET_TW_MATCH(sk, net, hash, acookie,
					saddr, daddr, ports, dif)) {
			if (unlikely(!atomic_inc_not_zero(&sk->sk_refcnt))) {
				sk = NULL;
				goto out;
			}
			if (unlikely(!INET_TW_MATCH(sk, net, hash, acookie,
				 saddr, daddr, ports, dif))) {
				sock_put(sk);
				goto begintw;
			}
			goto out;
		}
	}
	/*
	 * if the nulls value we got at the end of this lookup is
	 * not the expected one, we must restart lookup.
	 * We probably met an item that was moved to another chain.
	 */
	if (get_nulls_value(node) != slot)
		goto begintw;
	sk = NULL;
out:
	rcu_read_unlock();
	return sk;
}
EXPORT_SYMBOL_GPL(__inet_lookup_established);

/* called with local bh disabled */
static int __inet_check_established(struct inet_timewait_death_row *death_row,
				    struct sock *sk, __u16 lport,
				    struct inet_timewait_sock **twp)
{
	struct inet_hashinfo *hinfo = death_row->hashinfo;
	struct inet_sock *inet = inet_sk(sk);
	__be32 daddr = inet->rcv_saddr;
	__be32 saddr = inet->daddr;
	int dif = sk->sk_bound_dev_if;
	INET_ADDR_COOKIE(acookie, saddr, daddr)
	const __portpair ports = INET_COMBINED_PORTS(inet->dport, lport);
	struct net *net = sock_net(sk);
	unsigned int hash = inet_ehashfn(net, daddr, lport, saddr, inet->dport);
	struct inet_ehash_bucket *head = inet_ehash_bucket(hinfo, hash);
	spinlock_t *lock = inet_ehash_lockp(hinfo, hash);
	struct sock *sk2;
	const struct hlist_nulls_node *node;
	struct inet_timewait_sock *tw;

	spin_lock(lock);

	/* Check TIME-WAIT sockets first. */
	sk_nulls_for_each(sk2, node, &head->twchain) {
		tw = inet_twsk(sk2);

		if (INET_TW_MATCH(sk2, net, hash, acookie,
					saddr, daddr, ports, dif)) {
			if (twsk_unique(sk, sk2, twp))
				goto unique;
			else
				goto not_unique;
		}
	}
	tw = NULL;

	/* And established part... */
	sk_nulls_for_each(sk2, node, &head->chain) {
		if (INET_MATCH(sk2, net, hash, acookie,
					saddr, daddr, ports, dif))
			goto not_unique;
	}

unique:
	/* Must record num and sport now. Otherwise we will see
	 * in hash table socket with a funny identity. */
	inet->num = lport;
	inet->sport = htons(lport);
	sk->sk_hash = hash;
	WARN_ON(!sk_unhashed(sk));
	__sk_nulls_add_node_rcu(sk, &head->chain);
	spin_unlock(lock);
	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, 1);

	if (twp) {
		*twp = tw;
		NET_INC_STATS_BH(net, LINUX_MIB_TIMEWAITRECYCLED);
	} else if (tw) {
		/* Silly. Should hash-dance instead... */
		inet_twsk_deschedule(tw, death_row);
		NET_INC_STATS_BH(net, LINUX_MIB_TIMEWAITRECYCLED);

		inet_twsk_put(tw);
	}

	return 0;

not_unique:
	spin_unlock(lock);
	return -EADDRNOTAVAIL;
}

static inline u32 inet_sk_port_offset(const struct sock *sk)
{
	const struct inet_sock *inet = inet_sk(sk);
	return secure_ipv4_port_ephemeral(inet->rcv_saddr, inet->daddr,
					  inet->dport);
}

void __inet_hash_nolisten(struct sock *sk)
{
	struct inet_hashinfo *hashinfo = sk->sk_prot->h.hashinfo;
	struct hlist_nulls_head *list;
	spinlock_t *lock;
	struct inet_ehash_bucket *head;

	WARN_ON(!sk_unhashed(sk));

	sk->sk_hash = inet_sk_ehashfn(sk);
	head = inet_ehash_bucket(hashinfo, sk->sk_hash);
	list = &head->chain;
	lock = inet_ehash_lockp(hashinfo, sk->sk_hash);

	spin_lock(lock);
	__sk_nulls_add_node_rcu(sk, list);
	spin_unlock(lock);
	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, 1);
}
EXPORT_SYMBOL_GPL(__inet_hash_nolisten);

static void __inet_hash(struct sock *sk)
{
	struct inet_hashinfo *hashinfo = sk->sk_prot->h.hashinfo;
	struct inet_listen_hashbucket *ilb;
	int hash = 0;

	if (sk->sk_state != TCP_LISTEN) {
		__inet_hash_nolisten(sk);
		return;
	}

	hash = inet_sk_listen_hashfn(sk);
	if (sk->cpumask == 0) {
		WARN_ON(!sk_unhashed(sk));
		ilb = &hashinfo->listening_hash[hash];

		spin_lock(&ilb->lock);
		__sk_nulls_add_node_rcu(sk, &ilb->head);
		sock_prot_inuse_add(sock_net(sk), sk->sk_prot, 1);
		spin_unlock(&ilb->lock);

		//XIAOFENG6
		__get_cpu_var(hash_stats).global_listen_hash++;
		//XIAOFENG6
	} else {
		/*
 		 *  add to local listening hashtable 
  		 */
		struct inet_listen_hash_chunk *lis_hash_chk = NULL;
		int cpuid = 0, i = 0;

		for_each_possible_cpu(i) {
			if (sk->cpumask & ((unsigned long)1 << i))
				break;
		}
		cpuid = i;
		
		lis_hash_chk = per_cpu_ptr(hashinfo->local_listening_hash, cpuid);	
		ilb = &lis_hash_chk->listening_hash[hash];
		
		spin_lock(&ilb->lock);
		__sk_nulls_add_node_rcu(sk, &ilb->head);
		sock_prot_inuse_add(sock_net(sk), sk->sk_prot, 1);
		spin_unlock(&ilb->lock);

		//XIAOFENG6
		__get_cpu_var(hash_stats).local_listen_hash++;
		//XIAOFENG6
	}
}

void inet_hash(struct sock *sk)
{
	if (sk->sk_state != TCP_CLOSE) {
		local_bh_disable();
		__inet_hash(sk);
		local_bh_enable();
	}
}
EXPORT_SYMBOL_GPL(inet_hash);

void inet_unhash(struct sock *sk)
{
	struct inet_hashinfo *hashinfo = sk->sk_prot->h.hashinfo;
	spinlock_t *lock;
	int done;

	if (sk_unhashed(sk))
		return;

	if (sk->sk_state == TCP_LISTEN) {
		int hash = inet_sk_listen_hashfn(sk);
		if (sk->cpumask == 0) {
			lock = &hashinfo->listening_hash[hash].lock;
			//XIAOFENG6
			__get_cpu_var(hash_stats).global_listen_unhash++;
			//XIAOFENG6
		} else {
			struct inet_listen_hashbucket *ilh = NULL;
			struct inet_listen_hash_chunk *lis_hash_chk;
			int cpuid = 0, i = 0;

			for_each_possible_cpu(i) {
				if (sk->cpumask & ((unsigned long)1 << i))
					break;
			}
			cpuid = i;
				
			//printk(KERN_INFO"inet_unhash:cpuid=%d\n", cpuid);
			lis_hash_chk = per_cpu_ptr(hashinfo->local_listening_hash, cpuid);
			
			ilh = &lis_hash_chk->listening_hash[hash];
			lock = &ilh->lock;
			//XIAOFENG6
			__get_cpu_var(hash_stats).local_listen_unhash++;
			//XIAOFENG6
		}
	}
	else
		lock = inet_ehash_lockp(hashinfo, sk->sk_hash);

	spin_lock_bh(lock);
	done =__sk_nulls_del_node_init_rcu(sk);
	if (done)
		sock_prot_inuse_add(sock_net(sk), sk->sk_prot, -1);
	spin_unlock_bh(lock);
}
EXPORT_SYMBOL_GPL(inet_unhash);

int __inet_hash_connect(struct inet_timewait_death_row *death_row,
		struct sock *sk, u32 port_offset,
		int (*check_established)(struct inet_timewait_death_row *,
			struct sock *, __u16, struct inet_timewait_sock **),
		void (*hash)(struct sock *sk))
{
	struct inet_hashinfo *hinfo = death_row->hashinfo;
	const unsigned short snum = inet_sk(sk)->num;
	struct inet_bind_hashbucket *head;
	struct inet_bind_bucket *tb;
	int ret;
	struct net *net = sock_net(sk);

	if (!snum) {
		int i, remaining, low, high, port;
		static u32 hint;
		u32 offset = hint + port_offset;
		struct hlist_node *node;
		struct inet_timewait_sock *tw = NULL;

		DPRINTK(INFO, "Hint: %u - base offset: %u - new offset: %u\n", 
			hint, port_offset, offset);

		inet_get_local_port_range(&low, &high);
		remaining = (high - low) + 1;

		DPRINTK(INFO, "Port pool:%d [%d - %d]\n", remaining, low, high);

		local_bh_disable();
		for (i = 1; i <= remaining; i++) {
			port = low + (i + offset) % remaining;

			DPRINTK(INFO, "Target port %d\n", port);

			if (inet_is_reserved_local_port(port))
				continue;
			head = &hinfo->bhash[inet_bhashfn(net, port,
					hinfo->bhash_size)];
			spin_lock(&head->lock);

			/* Does not bother with rcv_saddr checks,
			 * because the established check is already
			 * unique enough.
			 */
			inet_bind_bucket_for_each(tb, node, &head->chain) {
				if (ib_net(tb) == net && tb->port == port) {
					if (tb->fastreuse >= 0)
						goto next_port;
					WARN_ON(hlist_empty(&tb->owners));
					if (!check_established(death_row, sk,
								port, &tw))
						goto ok;
					goto next_port;
				}
			}

			tb = inet_bind_bucket_create(hinfo->bind_bucket_cachep,
					net, head, port);
			if (!tb) {
				spin_unlock(&head->lock);
				break;
			}
			tb->fastreuse = -1;
			goto ok;

		next_port:
			spin_unlock(&head->lock);
		}
		local_bh_enable();

		return -EADDRNOTAVAIL;

ok:
		hint += i;

		DPRINTK(INFO, "Port selected:%u - hint updated: %u\n", port, hint);

		/* Head lock still held and bh's disabled */
		inet_bind_hash(sk, tb, port);
		if (sk_unhashed(sk)) {
			inet_sk(sk)->sport = htons(port);
			hash(sk);
		}
		spin_unlock(&head->lock);

		if (tw) {
			inet_twsk_deschedule(tw, death_row);
			inet_twsk_put(tw);
		}

		ret = 0;
		goto out;
	}

	head = &hinfo->bhash[inet_bhashfn(net, snum, hinfo->bhash_size)];
	tb  = inet_csk(sk)->icsk_bind_hash;
	spin_lock_bh(&head->lock);
	if (sk_head(&tb->owners) == sk && !sk->sk_bind_node.next) {
		hash(sk);
		spin_unlock_bh(&head->lock);
		return 0;
	} else {
		spin_unlock(&head->lock);
		/* No definite answer... Walk to established hash table */
		ret = check_established(death_row, sk, snum, NULL);
out:
		local_bh_enable();
		return ret;
	}
}


int fastsocket_inet_hash_connect(struct inet_timewait_death_row *death_row,
		struct sock *sk, u32 port_offset,
		int (*check_established)(struct inet_timewait_death_row *,
			struct sock *, __u16, struct inet_timewait_sock **),
		void (*hash)(struct sock *sk))
{
	struct inet_hashinfo *hinfo = death_row->hashinfo;
	const unsigned short snum = inet_sk(sk)->num;
	struct inet_bind_hashbucket *head;
	struct inet_bind_bucket *tb;
	int ret;
	struct net *net = sock_net(sk);

	//XIAOFENG6
	int cpu = smp_processor_id();
	//FIXME: CPU hot plug 
	int cpu_num = num_active_cpus();
	int round_cpu_num;

	unsigned int mask;
		
	round_cpu_num = cpu_num;

	if (!is_power_of_2(cpu_num))
		round_cpu_num = roundup_pow_of_two(cpu_num);

	mask = ~(round_cpu_num - 1);

	DPRINTK(INFO, "Total cpu num: %d - Round cpu num: %d - cpu mask : %x - Current cpu: %d\n", cpu_num, round_cpu_num, mask, cpu);

	//XIAOFENG6

	if (!snum) {
		int i, remaining, low, high, port;
		static u32 hint;
		//XIAOFENG6
		//u32 offset = hint + port_offset;
		u32 offset = hint + (port_offset & mask);
		//XIAOFENG6
		struct hlist_node *node;
		struct inet_timewait_sock *tw = NULL;

		//XIAOFENG6
		DPRINTK(INFO, "Hint: %u - base offset: %u - new offset: %u\n", 
			hint, port_offset, offset);

		inet_get_local_port_range(&low, &high);

		low &= mask;
		high &= mask;

		//remaining = (high - low) + 1;
		remaining = high - low;
		//XIAOFENG6

		DPRINTK(INFO, "Port pool:%d [%d - %d]\n", remaining, low, high);

		local_bh_disable();
		//XIAOFENG6
		//for (i = 1; i <= remaining; i++) {
		for (i = 0; i <= remaining; i = i + round_cpu_num) {
			//port = low + (i + offset) % remaining;
			port = low + (i + offset + cpu) % remaining;
			
			DPRINTK(INFO, "Target port %d\n", port);
		//XIAOFENG6
			if (inet_is_reserved_local_port(port))
				continue;
			head = &hinfo->bhash[inet_bhashfn(net, port,
					hinfo->bhash_size)];
			spin_lock(&head->lock);

			/* Does not bother with rcv_saddr checks,
			 * because the established check is already
			 * unique enough.
			 */
			inet_bind_bucket_for_each(tb, node, &head->chain) {
				if (ib_net(tb) == net && tb->port == port) {
					if (tb->fastreuse >= 0)
						goto next_port;
					WARN_ON(hlist_empty(&tb->owners));
					if (!check_established(death_row, sk,
								port, &tw))
						goto ok;
					goto next_port;
				}
			}

			tb = inet_bind_bucket_create(hinfo->bind_bucket_cachep,
					net, head, port);
			if (!tb) {
				spin_unlock(&head->lock);
				break;
			}
			tb->fastreuse = -1;
			goto ok;

		next_port:
			spin_unlock(&head->lock);
		}
		local_bh_enable();

		return -EADDRNOTAVAIL;

ok:
		//XIAOFENG6
		//hint += i;
		hint += (i + 1) * round_cpu_num;
		DPRINTK(INFO, "Port selected:%u - hint updated: %u\n", port, hint);
		//XIAOFENG6

		/* Head lock still held and bh's disabled */
		inet_bind_hash(sk, tb, port);
		if (sk_unhashed(sk)) {
			inet_sk(sk)->sport = htons(port);
			hash(sk);
		}
		spin_unlock(&head->lock);

		if (tw) {
			inet_twsk_deschedule(tw, death_row);
			inet_twsk_put(tw);
		}

		ret = 0;
		goto out;
	}

	head = &hinfo->bhash[inet_bhashfn(net, snum, hinfo->bhash_size)];
	tb  = inet_csk(sk)->icsk_bind_hash;
	spin_lock_bh(&head->lock);
	if (sk_head(&tb->owners) == sk && !sk->sk_bind_node.next) {
		hash(sk);
		spin_unlock_bh(&head->lock);
		return 0;
	} else {
		spin_unlock(&head->lock);
		/* No definite answer... Walk to established hash table */
		ret = check_established(death_row, sk, snum, NULL);
out:
		local_bh_enable();
		return ret;
	}
}

/*
 * Bind a port for a connect operation and hash it.
 */

//XIAOFENG6
extern int enable_receive_flow_deliver;
//XIAOFENG6

int inet_hash_connect(struct inet_timewait_death_row *death_row,
		      struct sock *sk)
{
	//XIAOFENG6
	int ret; 
	if (enable_receive_flow_deliver)
		ret = fastsocket_inet_hash_connect(death_row, sk, inet_sk_port_offset(sk),
				__inet_check_established, __inet_hash_nolisten);
	else
		ret = __inet_hash_connect(death_row, sk, inet_sk_port_offset(sk), 
				__inet_check_established, __inet_hash_nolisten);

	return ret;
	//XIAOFENG6
}

EXPORT_SYMBOL_GPL(inet_hash_connect);

//XIAOFENG6

static volatile unsigned cpu_id;

static struct inet_hash_stats *get_online(loff_t *pos)
{
	struct inet_hash_stats *rc = NULL;

	while (*pos < nr_cpu_ids)
		if (cpu_online(*pos)) {
			rc = &per_cpu(hash_stats, *pos);
			break;
		} else
			++*pos;
	cpu_id = *pos;

	return rc;
}

static void *hash_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	++*pos;
	return get_online(pos);
}

static void hash_seq_stop(struct seq_file *seq, void *v)
{

}

static void *hash_seq_start(struct seq_file *seq, loff_t *pos)
{
	seq_printf(seq, "%s\t%-15s%-15s%-15s%-15s%-15s%-15s%-15s%-15s\n",
		"CPU", "Loc_lst_lookup", "Glo_lst_lookup", 
		"Com_accetp", "Com_accept_F", "Loc_accept", 
		"Loc_accept_F", "Glo_accept", "Glo_accept_F");
		
	cpu_id = 0;

	return get_online(pos);
}

static int hash_seq_show(struct seq_file *seq, void *v)
{
	struct inet_hash_stats *s = v;

	seq_printf(seq, "%u\t%-15lu%-15lu%-15lu%-15lu%-15lu%-15lu%-15lu%-15lu\n", 
		cpu_id, s->local_listen_lookup, s->global_listen_lookup, 
		s->common_accept, s->common_accept_failed, s->local_accept, 
		s->local_accept_failed, s->global_accept, s->global_accept_failed);

	return 0;
}
static const struct seq_operations hash_seq_ops = {
	.start = hash_seq_start,
	.next  = hash_seq_next,
	.stop  = hash_seq_stop,
	.show  = hash_seq_show,
};

static int hash_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &hash_seq_ops);
}

ssize_t hash_reset(struct file *file, const char __user *buf, size_t size, loff_t *ppos)
{
	int cpu;

	for_each_online_cpu(cpu)
		memset(&per_cpu(hash_stats, cpu), 0, sizeof(struct inet_hash_stats));

	return 1;
}

static const struct file_operations hash_seq_fops = {
	.owner	 = THIS_MODULE,
	.open    = hash_seq_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release,
	.write   = hash_reset,
};

static int __net_init inet_hash_proc_net_init(struct net *net)
{	
	int rc = -ENOMEM;

	if (!proc_net_fops_create(net, "hash_stat", S_IRUGO, &hash_seq_fops))
		goto out;

	rc = 0;

out:
	return rc;
}

static void __net_exit inet_hash_proc_net_exit(struct net *net)
{
	proc_net_remove(net, "hash_stat");
}


static struct pernet_operations __net_initdata inet_hash_proc_ops = {
	.init = inet_hash_proc_net_init,
	.exit = inet_hash_proc_net_exit,
};

static int inet_hash_proc_init(void)
{
	return register_pernet_subsys(&inet_hash_proc_ops);
}

//XIAOFENG6

void inet_hashinfo_init(struct inet_hashinfo *h)
{
	int i;

	//XIAOFENG6
	inet_hash_proc_init();
	//XIAOFENG6

	atomic_set(&h->bsockets, 0);
	h->local_listening_hash = alloc_percpu(struct inet_listen_hash_chunk);

	/*
 	 * Initialise local listening hash 
 	 */
	for_each_possible_cpu(i) {
		struct inet_listen_hash_chunk *chk = per_cpu_ptr(h->local_listening_hash, i);
		
		int k = 0;
		for (k = 0; k < INET_LHTABLE_SIZE; k++) {
			spin_lock_init(&chk->listening_hash[k].lock);
			INIT_HLIST_NULLS_HEAD(&chk->listening_hash[k].head,
					      k + LISTENING_NULLS_BASE);
		}
	}

	for (i = 0; i < INET_LHTABLE_SIZE; i++) {
		spin_lock_init(&h->listening_hash[i].lock);
		INIT_HLIST_NULLS_HEAD(&h->listening_hash[i].head,
				      i + LISTENING_NULLS_BASE);
	}
}

EXPORT_SYMBOL_GPL(inet_hashinfo_init);
