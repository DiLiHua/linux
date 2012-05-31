/*  
 *  nfdbus.c - Netfilter module for AF_DBUS.
 */

#define DRIVER_AUTHOR "Alban Crequy"
#define DRIVER_DESC   "Netfilter module for AF_DBUS"

#include "nfdbus.h"

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/connector.h>
#include <net/af_bus.h>

#include "message.h"
#include "matchrule.h"

static struct nf_hook_ops nfho_dbus;

static struct cb_id cn_cmd_id = { CN_IDX_NFDBUS, CN_VAL_NFDBUS };

/* Scoped by AF_BUS address */
struct hlist_head matchrules_table[BUS_HASH_SIZE];

static struct bus_match_maker *find_match_maker(struct sockaddr_bus *addr,
		bool create)
{
	u64 hash;
	struct hlist_node *node;
	struct bus_match_maker *matchmaker;
	int path_len = strlen(addr->sbus_path);

	hash = csum_partial(addr->sbus_path,
	                    strlen(addr->sbus_path), 0);
	hash ^= addr->sbus_addr.s_addr;
	hash ^= hash >> 32;
	hash ^= hash >> 16;
	hash ^= hash >> 8;
	hash &= 0xff;

	hlist_for_each_entry(matchmaker, node, &matchrules_table[hash],
			     table_node) {
		if (addr->sbus_family == matchmaker->addr.sbus_family &&
		    addr->sbus_addr.s_addr == matchmaker->addr.sbus_addr.s_addr &&
		    !memcmp(addr->sbus_path, matchmaker->addr.sbus_path,
			   path_len)) {
			pr_debug("Found matchmaker for hash %llu", hash);
			return matchmaker;
		}
	}

	if (!create) {
		pr_debug("Matchmaker for hash %llu not found", hash);
		return NULL;
	}

	matchmaker = bus_matchmaker_new();
	matchmaker->addr.sbus_family = addr->sbus_family;
	matchmaker->addr.sbus_addr.s_addr = addr->sbus_addr.s_addr;
	memcpy(matchmaker->addr.sbus_path, addr->sbus_path, BUS_PATH_MAX);
	
	pr_debug("Create new matchmaker for hash %llu\n", hash);
	hlist_add_head(&matchmaker->table_node, &matchrules_table[hash]);
	return matchmaker;
}

static unsigned int dbus_filter(unsigned int hooknum,
                                struct sk_buff *skb,
                                const struct net_device *in,
                                const struct net_device *out,
                                int (*okfn)(struct sk_buff *))
{
	struct bus_send_context	*sendctx;
	struct bus_match_maker *matchmaker = NULL;
	struct bus_match_maker *sender = NULL;
        struct dbus_message msg = {0,};
        unsigned char *data;
        size_t len;
        int err;

	if (!skb->sk || skb->sk->sk_family != PF_BUS) {
		WARN(1, "netfilter_dbus received an invalid skb");
		return NF_DROP;
	}

        data = skb->data;
	sendctx = BUSCB(skb).sendctx;
	if (!sendctx || !sendctx->sender || !sendctx->sender_socket) {
		WARN(1, "netfilter_dbus received an AF_BUS packet"
		     " without context. This is a bug. Dropping the"
			" packet.");
        	return NF_DROP;
	}
	if (sendctx->sender_socket->sk->sk_protocol != BUS_PROTO_DBUS) {
		/* This kernel module is for D-Bus. It must not
		 * interfere with other users of AF_BUS. */
        	return NF_ACCEPT;
	}
	if (sendctx->recipient) {
		matchmaker = find_match_maker(sendctx->recipient, false);
        }
        len =  skb_tail_pointer(skb) - data;

	if (sendctx->to_master) {
       		pr_debug("AF_BUS packet to the bus master. ACCEPT.\n");
               	return NF_ACCEPT;
	}

	if (!sendctx->multicast && !sendctx->bus_master_side) {
       		pr_debug("AF_BUS packet from a peer to a peer (unicast). ACCEPT.\n");
               	return NF_ACCEPT;
	}

        err = dbus_message_parse(data, len, &msg);
        if (err) {
		if (sendctx->bus_master_side) {
	       		pr_debug("AF_BUS packet from bus master is not parsable. ACCEPT.\n");
	                return NF_ACCEPT;
		} else {
	       		pr_debug("AF_BUS packet from peer is not parsable. DROP.\n");
	                return NF_DROP;
		}
	}

	if (sendctx->bus_master_side) {
		if (msg.name_acquired) {
       			pr_debug("New name: %s [%p %p].\n",
			       msg.name_acquired, sendctx->sender, sendctx->recipient);

			sender = find_match_maker(sendctx->sender, true);
			bus_matchmaker_add_name(sender, msg.name_acquired);
		}
		if (msg.name_lost) {
       			pr_debug("Lost name: %s [%p %p].\n",
			       msg.name_lost, sendctx->sender, sendctx->recipient);

			sender = find_match_maker(sendctx->sender, true);
			bus_matchmaker_remove_name(sender, msg.name_acquired);
		}

       		pr_debug("AF_BUS packet '%s' from the bus master. ACCEPT.\n",
		       msg.member ? msg.member : "");
               	return NF_ACCEPT;
	}

       	pr_debug("Multicast AF_BUS packet, %d bytes, "
	       "considering recipient %lld...\n", len,
	       sendctx->recipient ? sendctx->recipient->sbus_addr.s_addr : 0);

        pr_debug("Message type %d %s->%s [iface: %s][member: %s][matchmaker=%p]...\n",
	       msg.type,
	       msg.sender ? msg.sender : "",
	       msg.destination ? msg.destination : "",
	       msg.interface ? msg.interface : "",
	       msg.member ? msg.member : "",
	       matchmaker);

	if (!matchmaker) {
       		pr_debug("No match rules for this recipient. DROP.\n");
		return NF_DROP;
	}

	sender = find_match_maker(sendctx->sender, true);
        err = bus_matchmaker_filter(matchmaker, sender, &msg);
        if (err) {
       		pr_debug("Matchmaker: ACCEPT.\n");
                return NF_ACCEPT;
        } else {
       		pr_debug("Matchmaker: DROP.\n");
                return NF_DROP;
	}
}

/* Taken from drbd_nl_send_reply() */
static void nfdbus_nl_send_reply(struct cn_msg *msg, int ret_code)
{
	char buffer[sizeof(struct cn_msg)+sizeof(struct nfdbus_nl_cfg_reply)];
	struct cn_msg *cn_reply = (struct cn_msg *) buffer;
	struct nfdbus_nl_cfg_reply *reply =
		(struct nfdbus_nl_cfg_reply *)cn_reply->data;
	int rr;

	memset(buffer, 0, sizeof(buffer));
	cn_reply->id = msg->id;

	cn_reply->seq = msg->seq;
	cn_reply->ack = msg->ack  + 1;
	cn_reply->len = sizeof(struct nfdbus_nl_cfg_reply);
	cn_reply->flags = 0;

	reply->ret_code = ret_code;

	rr = cn_netlink_send(cn_reply, 0, GFP_NOIO);
	if (rr && rr != -ESRCH)
		pr_debug("nfdbus: cn_netlink_send()=%d\n", rr);
}

static void cn_cmd_cb(struct cn_msg *msg, struct netlink_skb_parms *nsp)
{
	struct nfdbus_nl_cfg_req *nlp = (struct nfdbus_nl_cfg_req *)msg->data;
        struct cn_msg *cn_reply;
	struct nfdbus_nl_cfg_reply *reply;
	int retcode, rr;
	int reply_size = sizeof(struct cn_msg)
		+ sizeof(struct nfdbus_nl_cfg_reply);

	pr_debug("nfdbus: cn_cmd_cb called nsp->pid=%d.\n", nsp->pid);

	if (!try_module_get(THIS_MODULE)) {
		pr_debug(KERN_ERR "nfdbus: try_module_get() failed!\n");
		return;
	}

	/*
        if (!cap_raised(current_cap(), CAP_SYS_ADMIN)) {
		pr_debug(KERN_ERR "nfdbus: no CAP_SYS_ADMIN!\n");
		retcode = EPERM;
		goto fail;
	}
        */

        cn_reply = kzalloc(reply_size, GFP_KERNEL);
        if (!cn_reply) {
                retcode = ENOMEM;
                goto fail;
        }
	reply = (struct nfdbus_nl_cfg_reply *) cn_reply->data;

        if (msg->len < sizeof(struct nfdbus_nl_cfg_req)) {
	        reply->ret_code = EINVAL;
        } else if (nlp->cmd == NFDBUS_CMD_ADDMATCH) {
                struct bus_match_rule *rule;
		struct bus_match_maker *matchmaker;
	        reply->ret_code = 0;
                pr_debug("%s: %lu: [pid = %d  uid = %d] "
                       "idx=%x, val=%x, seq=%u, ack=%u, len=%d: %s.\n",
                       __func__, jiffies, nsp->creds.pid, nsp->creds.uid,
                       msg->id.idx, msg->id.val,
                       msg->seq, msg->ack, msg->len,
                       msg->len ? (char *)nlp->data : "");

                if (msg->len == 0)
                       reply->ret_code = EINVAL;

                rule = bus_match_rule_parse(nlp->data);
		if (rule) {
			matchmaker = find_match_maker(&nlp->addr, true);
			pr_debug("Add match rule for matchmaker %p\n", matchmaker);
	                bus_matchmaker_add_rule(matchmaker, rule);
		} else {
	        	reply->ret_code = EINVAL;
		}
        } else if (nlp->cmd == NFDBUS_CMD_REMOVEMATCH) {
                struct bus_match_rule *rule;
		struct bus_match_maker *matchmaker;

                rule = bus_match_rule_parse(nlp->data);
		matchmaker = find_match_maker(&nlp->addr, false);
		if (!matchmaker)
			reply->ret_code = EINVAL;
		else
			bus_matchmaker_remove_rule_by_value(matchmaker, rule);
		bus_match_rule_unref(rule);
		
	        reply->ret_code = 0;
        } else {
	        reply->ret_code = EINVAL;
        }

	cn_reply->id = msg->id;
	cn_reply->seq = msg->seq;
	cn_reply->ack = msg->ack  + 1;
	cn_reply->len = sizeof(struct nfdbus_nl_cfg_reply);
	cn_reply->flags = 0;

	rr = cn_netlink_reply(cn_reply, nsp->pid, GFP_KERNEL);
	if (rr && rr != -ESRCH)
		pr_debug("nfdbus: cn_netlink_send()=%d\n", rr);
	pr_debug("nfdbus: cn_netlink_reply(pid=%d)=%d\n", nsp->pid, rr);

	kfree(cn_reply);
	module_put(THIS_MODULE);
        return;
fail:
	nfdbus_nl_send_reply(msg, retcode);
	module_put(THIS_MODULE);
}

static int __init nfdbus_init(void)
{
        int err;

        pr_debug("Loading netfilter_dbus\n");

        /* Install D-Bus netfilter hook */
        nfho_dbus.hook     = dbus_filter;
        nfho_dbus.hooknum  = NF_BUS_SENDING;
        nfho_dbus.pf       = NFPROTO_BUS; /* Do not use PF_BUS, you fool! */
        nfho_dbus.priority = 0;
        nfho_dbus.owner = THIS_MODULE;
        err = nf_register_hook(&nfho_dbus);
        if (err)
                return err;
        pr_debug("Netfilter hook for D-Bus: installed.\n");

        /* Install connector hook */
        err = cn_add_callback(&cn_cmd_id, "nfdbus", cn_cmd_cb);
        if (err)
                goto err_cn_cmd_out;
        pr_debug("Connector hook: installed.\n");

        return 0;

err_cn_cmd_out:
        nf_unregister_hook(&nfho_dbus);

        return err;
}

static void __exit nfdbus_cleanup(void)
{
        nf_unregister_hook(&nfho_dbus);

        cn_del_callback(&cn_cmd_id);

        pr_debug("Unloading netfilter_dbus\n");
}

module_init(nfdbus_init);
module_exit(nfdbus_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_ALIAS("net-pf-" __stringify(PF_BUS) "-proto-" __stringify(BUS_PROTO_DBUS));
