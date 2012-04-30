/*
 * Sysctl interface to net af_bus subsystem.
 *
 * Based on Sysctl interface to net af_bus subsystem (net/unix/sysctl_net_unix.c).
 *
 */

#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/sysctl.h>

#include <net/af_bus.h>

static ctl_table bus_table[] = {
	{
		.procname	= "max_dgram_qlen",
		.data		= &init_net.unx.sysctl_max_dgram_qlen,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec
	},
	{ }
};

static struct ctl_path bus_path[] = {
	{ .procname = "net", },
	{ .procname = "bus", },
	{ },
};

int __net_init bus_sysctl_register(struct net *net)
{
	struct ctl_table *table;

	table = kmemdup(bus_table, sizeof(bus_table), GFP_KERNEL);
	if (table == NULL)
		goto err_alloc;

	table[0].data = &net->unx.sysctl_max_dgram_qlen;
	net->unx.ctl = register_net_sysctl_table(net, bus_path, table);
	if (net->unx.ctl == NULL)
		goto err_reg;

	return 0;

err_reg:
	kfree(table);
err_alloc:
	return -ENOMEM;
}

void bus_sysctl_unregister(struct net *net)
{
	struct ctl_table *table;

	table = net->unx.ctl->ctl_table_arg;
	unregister_sysctl_table(net->unx.ctl);
	kfree(table);
}
