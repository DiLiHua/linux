#ifndef _LINUX_BUS_H
#define _LINUX_BUS_H

#include <linux/socket.h>

/* 'protocol' to use in socket(AF_BUS, SOCK_SEQPACKET, protocol) */
#define BUS_PROTO_NONE	0
#define BUS_PROTO_DBUS	1
#define BUS_PROTO_MAX	1

#define BUS_PATH_MAX	108

/* Bus address */
struct bus_addr {
	u64 s_addr; /* 16-bit prefix + 48-bit client address */
};

/* Structure describing an AF_BUS socket address. */
struct sockaddr_bus {
	__kernel_sa_family_t sbus_family; /* AF_BUS */
	struct bus_addr      sbus_addr;   /* bus address */
	char sbus_path[BUS_PATH_MAX];  /* pathname */
};

#endif /* _LINUX_BUS_H */
