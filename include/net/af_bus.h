#ifndef __LINUX_NET_AFBUS_H
#define __LINUX_NET_AFBUS_H

#include <linux/socket.h>
#include <linux/un.h>
#include <linux/bus.h>
#include <linux/mutex.h>
#include <net/sock.h>

extern void bus_inflight(struct file *fp);
extern void bus_notinflight(struct file *fp);
extern void bus_gc(void);
extern void wait_for_bus_gc(void);
extern struct sock *bus_get_socket(struct file *filp);
extern struct sock *bus_peer_get(struct sock *);

#define BUS_HASH_SIZE	256
#define BUS_MASTER_ADDR 0x0
#define BUS_PREFIX_BITS 16
#define BUS_CLIENT_BITS 48
#define BUS_PREFIX_MASK 0xffff000000000000
#define BUS_CLIENT_MASK 0x0000ffffffffffff

/* AF_BUS socket options */
#define BUS_ADD_ADDR 1
#define BUS_JOIN_BUS 2
#define BUS_DEL_ADDR 3

#define NF_BUS_SENDING 1

/*
 * AF_BUS ioctl() commands
 *
 * include/linux/sockios.h reserves 16 protocol private ioctl numbers
 * from 0x89E0 to 89EF.
 * So, let's use this range for the AF_BUS ioctl commands.
 */
#define SIOCSINQ 0x89E0

extern unsigned int bus_tot_inflight;
extern spinlock_t bus_table_lock;
extern struct hlist_head bus_socket_table[BUS_HASH_SIZE + 1];

struct bus_address {
	atomic_t	refcnt;
	int		len;
	unsigned	hash;
	struct hlist_node addr_node;
	struct hlist_node table_node;
	struct sock  *sock;
	struct sockaddr_bus name[0];
};


struct bus_send_context {
	struct socket *sender_socket;
	struct sock_iocb *siocb;
	long timeo;
	int max_level;
	int namelen;
	unsigned hash;
	struct sock *other;
	struct sockaddr_bus	*sender;
	struct sockaddr_bus	*recipient;
	unsigned int		authenticated:1;
	unsigned int		bus_master_side:1;
	unsigned int		to_master:1;
	unsigned int		multicast:1;
};

struct bus_skb_parms {
	struct pid		*pid;		/* Skb credentials	*/
	const struct cred	*cred;
	struct scm_fp_list	*fp;		/* Passed files		*/
#ifdef CONFIG_SECURITY_NETWORK
	u32			secid;		/* Security ID		*/
#endif
	struct bus_send_context	*sendctx;
};

#define BUSCB(skb) 	(*(struct bus_skb_parms *)&((skb)->cb))
#define BUSSID(skb)	(&BUSCB((skb)).secid)

#define bus_state_lock(s)	spin_lock(&bus_sk(s)->lock)
#define bus_state_unlock(s)	spin_unlock(&bus_sk(s)->lock)
#define bus_state_lock_nested(s) \
				spin_lock_nested(&bus_sk(s)->lock, \
				SINGLE_DEPTH_NESTING)

struct bus {
	struct sock		*master;
        /*
	 * List of (struct bus_sock)->bus_node
	 * Only sockets that were allowed to join the bus by the bus
	 * master socket are members of this list.
	 */
	struct hlist_head       peers;
	spinlock_t		lock;
	struct kref             kref;
	atomic64_t              addr_cnt;
};

/* The AF_BUS socket */
struct bus_sock {
	/* WARNING: sk has to be the first member */
	struct sock		sk;
	struct bus_address     *addr;
	struct hlist_head       addr_list;
	struct path		path;
	struct mutex		readlock;
	struct sock		*peer;
	struct sock		*other;
	struct list_head	link;
	atomic_long_t		inflight;
	spinlock_t		lock;
	unsigned int		gc_candidate : 1;
	unsigned int		gc_maybe_cycle : 1;
	unsigned char		recursion_level;
	struct socket_wq	peer_wq;
	struct bus              *bus;
	bool                    bus_master;
	bool                    bus_master_side;
	bool                    authenticated;
	struct hlist_node	bus_node;
};
#define bus_sk(__sk) ((struct bus_sock *)__sk)

#define peer_wait peer_wq.wait

long bus_inq_len(struct sock *sk);
long bus_outq_len(struct sock *sk);

#ifdef CONFIG_SYSCTL
extern int bus_sysctl_register(struct net *net);
extern void bus_sysctl_unregister(struct net *net);
#else
static inline int bus_sysctl_register(struct net *net) { return 0; }
static inline void bus_sysctl_unregister(struct net *net) {}
#endif
#endif
