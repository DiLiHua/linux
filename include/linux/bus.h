#ifndef _LINUX_BUS_H
#define _LINUX_BUS_H

#include <linux/socket.h>

/* Bus address */
struct bus_addr {
	u64 s_addr; /* 16-bit prefix + 48-bit client address */
};

/* Structure describing an AF_BUS socket address. */
struct sockaddr_bus {
	__kernel_sa_family_t sbus_family; /* AF_BUS */
	u64                  sbus_scope;  /* scope */
	struct bus_addr      sbus_addr;   /* bus address */
};

#endif /* _LINUX_BUS_H */
