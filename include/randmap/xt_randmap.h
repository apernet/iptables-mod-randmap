#ifndef __HN2_XT_RANDMAP__
#define __HN2_XT_RANDMAP__

#include <linux/netfilter.h>

enum randmap_mangle_type {
	RANDMAP_MGT_SRC,
	RANDMAP_MGT_DST,
	RANDMAP_MGT_MAX,
};

union randmap_inet_addr {
	__u32		all[4];
	__be32		ip;
	__be32		ip6[4];
	struct in_addr	in;
	struct in6_addr	in6;
};

union randmap_mangle_proto {
	/* Add other protocols here. */
	__be16 all;

	struct {
		__be16 port;
	} tcp;
	struct {
		__be16 port;
	} udp;
	struct {
		__be16 port;
	} dccp;
	struct {
		__be16 port;
	} sctp;
};

#define RANDMAP_MANGLE_IP			(1 << 0)
#define RANDMAP_MANGLE_PROTO		(1 << 1)

struct randmap_mangle_range {
	__u32 flags; // RANDMAP_MANGLE_*
	union randmap_inet_addr		net;
	union randmap_inet_addr     mask;
	__u16					 	min_proto;
	__u16						max_proto;
};

struct randmap_info {
	struct randmap_mangle_range ranges[RANDMAP_MGT_MAX];
};


#endif /* __HN2_XT_RANDMAP__ */