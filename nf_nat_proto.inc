// SPDX-License-Identifier: GPL-2.0-only
/* (C) 1999-2001 Paul `Rusty' Russell
 * (C) 2002-2006 Netfilter Core Team <coreteam@netfilter.org>
 * (C) 2022 Haruue Icymoon <i@haruue.moe>
 */

/* Most of the codes here are copied from linux-v5.18.14/net/netfilter/nf_nat_proto.c
 * with the conntrack dependency removed to make it stateless. */

#include <linux/types.h>
#include <linux/export.h>
#include <linux/init.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>

#include <linux/dccp.h>
#include <linux/sctp.h>
#include <net/sctp/checksum.h>

#include <linux/netfilter.h>

#include <linux/ipv6.h>
#include <linux/netfilter_ipv6.h>
#include <net/checksum.h>
#include <net/ip6_checksum.h>
#include <net/ip6_route.h>
#include <net/xfrm.h>
#include <net/ipv6.h>

struct randmap_proto_addr {
	union randmap_inet_addr		addr;
	union randmap_mangle_proto	proto;
};

enum randmap_l3family {
	RANDMAP_L3FAMILY_IP4 = 4,
	RANDMAP_L3FAMILY_IP6 = 6,
};

struct randmap_mangle_context {
	enum randmap_l3family l3family;
	__u8 l4proto;

	__u32 						mangle_flags[RANDMAP_MGT_MAX];
	struct randmap_proto_addr	origin[RANDMAP_MGT_MAX];
	struct randmap_proto_addr	mangled[RANDMAP_MGT_MAX];
};

static void nf_csum_update(struct sk_buff *skb, __sum16 *check, const struct randmap_mangle_context *ctx);

static void
__udp_manip_pkt(struct sk_buff *skb, struct udphdr *hdr, struct randmap_mangle_context *ctx)
{
	__be16 *portptr, newport;
	unsigned int i;

	for (i = 0; i < RANDMAP_MGT_MAX; i++) {
		if (i == RANDMAP_MGT_SRC) {
			portptr = &hdr->source;
		} else if (i == RANDMAP_MGT_DST) {
			portptr = &hdr->dest;
		} else {
			WARN_ONCE(1, "randmap: __udp_manip_pkt: invalid mangle type %d\n", i);
			portptr = NULL;
		}

		if (portptr != NULL) {
			ctx->origin[i].proto.udp.port = *portptr;

			if ((ctx->mangle_flags[i] & RANDMAP_MANGLE_PROTO) != 0) {
				newport = ctx->mangled[i].proto.udp.port;
				inet_proto_csum_replace2(&hdr->check, skb, *portptr, newport, false);
				*portptr = newport;
			}
		}
	}

	nf_csum_update(skb, &hdr->check, ctx);
}

static bool udp_manip_pkt(struct sk_buff *skb, unsigned int hdroff, struct randmap_mangle_context *ctx)
{
	struct udphdr *hdr;

	if (skb->len < hdroff + sizeof(*hdr))
		return false;

	if (skb_ensure_writable(skb, hdroff + sizeof(*hdr)))
		return false;

	hdr = (struct udphdr *)(skb->data + hdroff);
	__udp_manip_pkt(skb, hdr, ctx);

	return true;
}

static bool udplite_manip_pkt(struct sk_buff *skb, unsigned int hdroff, struct randmap_mangle_context *ctx)
{
#ifdef CONFIG_NF_CT_PROTO_UDPLITE
	struct udphdr *hdr;

	if (skb_ensure_writable(skb, hdroff + sizeof(*hdr)))
		return false;

	hdr = (struct udphdr *)(skb->data + hdroff);
	__udp_manip_pkt(skb, hdr, ctx);
#endif
	return true;
}

static bool
sctp_manip_pkt(struct sk_buff *skb, unsigned int hdroff, struct randmap_mangle_context *ctx)
{
#ifdef CONFIG_NF_CT_PROTO_SCTP
	struct sctphdr *hdr;
	int hdrsize = 8;
	unsigned int i;
	__be16 *portptr;

	if (skb->len < hdroff + hdrsize)
		return false;

	/* This could be an inner header returned in imcp packet; in such
	 * cases we cannot update the checksum field since it is outside
	 * of the 8 bytes of transport layer headers we are guaranteed.
	 */
	if (skb->len >= hdroff + sizeof(*hdr))
		hdrsize = sizeof(*hdr);

	if (skb_ensure_writable(skb, hdroff + hdrsize))
		return false;

	hdr = (struct sctphdr *)(skb->data + hdroff);

	for (i = 0; i < RANDMAP_MGT_MAX; i++) {
		if (i == RANDMAP_MGT_SRC) {
			portptr = &hdr->source;
		} else if (i == RANDMAP_MGT_DST) {
			portptr = &hdr->dest;
		} else {
			WARN_ONCE(1, "randmap: sctp_manip_pkt: invalid mangle type %d\n", i);
			portptr = NULL;
		}

		if (portptr != NULL) {
			ctx->origin[i].proto.sctp.port = *portptr;

			if ((ctx->mangle_flags[i] & RANDMAP_MANGLE_PROTO) != 0) {
				*portptr = ctx->mangled[i].proto.sctp.port;
			}
		}
	}

	if (hdrsize < sizeof(*hdr))
		return true;

	if (skb->ip_summed != CHECKSUM_PARTIAL) {
		hdr->checksum = sctp_compute_cksum(skb, hdroff);
		skb->ip_summed = CHECKSUM_NONE;
	}

#endif
	return true;
}

static bool
tcp_manip_pkt(struct sk_buff *skb, unsigned int hdroff, struct randmap_mangle_context *ctx)
{
	struct tcphdr *hdr;
	__be16 *portptr, newport;
	int hdrsize = 8; /* TCP connection tracking guarantees this much */
	unsigned int i;

	if (skb->len < hdroff + hdrsize)
		return false;

	/* this could be a inner header returned in icmp packet; in such
	   cases we cannot update the checksum field since it is outside of
	   the 8 bytes of transport layer headers we are guaranteed */
	if (skb->len >= hdroff + sizeof(struct tcphdr))
		hdrsize = sizeof(struct tcphdr);

	if (skb_ensure_writable(skb, hdroff + hdrsize))
		return false;

	hdr = (struct tcphdr *)(skb->data + hdroff);

	for (i = 0; i < RANDMAP_MGT_MAX; i++) {
		if (i == RANDMAP_MGT_SRC) {
			portptr = &hdr->source;
		} else if (i == RANDMAP_MGT_DST) {
			portptr = &hdr->dest;
		} else {
			WARN_ONCE(1, "randmap: tcp_manip_pkt: invalid mangle type %d\n", i);
			portptr = NULL;
		}

		if (portptr != NULL) {
			ctx->origin[i].proto.tcp.port = *portptr;

			if ((ctx->mangle_flags[i] & RANDMAP_MANGLE_PROTO) != 0) {
				newport = ctx->mangled[i].proto.tcp.port;

				if (hdrsize < sizeof(*hdr))
					continue;

				inet_proto_csum_replace2(&hdr->check, skb, *portptr, newport, false);
				*portptr = newport;
			}
		}
	}

	if (hdrsize < sizeof(*hdr))
		return true;

	nf_csum_update(skb, &hdr->check, ctx);
	return true;
}

static bool
dccp_manip_pkt(struct sk_buff *skb, unsigned int hdroff, struct randmap_mangle_context *ctx)
{
#ifdef CONFIG_NF_CT_PROTO_DCCP
	struct dccp_hdr *hdr;
	__be16 *portptr, newport;
	int hdrsize = 8; /* DCCP connection tracking guarantees this much */
	unsigned int i;

	if (skb->len < hdroff + hdrsize)
		return false;

	if (skb->len >= hdroff + sizeof(struct dccp_hdr))
		hdrsize = sizeof(struct dccp_hdr);

	if (skb_ensure_writable(skb, hdroff + hdrsize))
		return false;

	hdr = (struct dccp_hdr *)(skb->data + hdroff);

	for (i = 0; i < RANDMAP_MGT_MAX; i++) {
		if (i == RANDMAP_MGT_SRC) {
			portptr = &hdr->dccph_sport;
		} else if (i == RANDMAP_MGT_DST) {
			portptr = &hdr->dccph_dport;
		} else {
			WARN_ONCE(1, "randmap: dccp_manip_pkt: invalid mangle type %d\n", i);
			portptr = NULL;
		}

		if (portptr != NULL) {
			ctx->origin[i].proto.dccp.port = *portptr;

			if ((ctx->mangle_flags[i] & RANDMAP_MANGLE_PROTO) != 0) {
				newport = ctx->mangled[i].proto.dccp.port;

				if (hdrsize < sizeof(*hdr))
					continue;

				inet_proto_csum_replace2(&hdr->dccph_checksum, skb, *portptr, newport, false);
				*portptr = newport;
			}
		}
	}

	if (hdrsize < sizeof(*hdr))
		return true;

	nf_csum_update(skb, &hdr->dccph_checksum, ctx);
#endif
	return true;
}

static bool
icmp_manip_pkt(struct sk_buff *skb, unsigned int hdroff, struct randmap_mangle_context *ctx)
{
	// icmp4 don't checksum the pseudohdr, so we don't need to do anything here
	return true;
}

static bool
icmpv6_manip_pkt(struct sk_buff *skb, unsigned int hdroff, struct randmap_mangle_context *ctx)
{
	struct icmp6hdr *hdr;

	if (skb->len < hdroff + sizeof(*hdr))
		return false;

	if (skb_ensure_writable(skb, hdroff + sizeof(*hdr)))
		return false;

	hdr = (struct icmp6hdr *)(skb->data + hdroff);
	nf_csum_update(skb, &hdr->icmp6_cksum, ctx);
	return true;
}

static bool l4proto_manip_pkt(struct sk_buff *skb, unsigned int hdroff, struct randmap_mangle_context *ctx)
{
	switch (ctx->l4proto) {
	case IPPROTO_TCP:
		return tcp_manip_pkt(skb, hdroff, ctx);
	case IPPROTO_UDP:
		return udp_manip_pkt(skb, hdroff, ctx);
	case IPPROTO_UDPLITE:
		return udplite_manip_pkt(skb, hdroff, ctx);
	case IPPROTO_SCTP:
		return sctp_manip_pkt(skb, hdroff, ctx);
	case IPPROTO_ICMP:
		return icmp_manip_pkt(skb, hdroff, ctx);
	case IPPROTO_ICMPV6:
		return icmpv6_manip_pkt(skb, hdroff, ctx);
	case IPPROTO_DCCP:
		return dccp_manip_pkt(skb, hdroff, ctx);
	}

	/* If we don't know protocol -- no error, pass it unmodified. */
	return true;
}

static bool nf_nat_ipv4_manip_pkt(struct sk_buff *skb, unsigned int iphdroff, struct randmap_mangle_context *ctx)
{
	struct iphdr *iph;
	unsigned int hdroff;
	unsigned int i;
	__be32 *addrptr, newaddr;

	if (skb->len < iphdroff + sizeof(*iph))
		return false;

	if (skb_ensure_writable(skb, iphdroff + sizeof(*iph)))
		return false;

	iph = (void *)skb->data + iphdroff;
	hdroff = iphdroff + iph->ihl * 4;

	ctx->l4proto = iph->protocol;

	if ((iph->frag_off & htons((1<<13)-1)) == 0 &&
	    !l4proto_manip_pkt(skb, hdroff, ctx))
		return false;
	iph = (void *)skb->data + iphdroff;

	for (i = 0; i < RANDMAP_MGT_MAX; i++) {
		if (i == RANDMAP_MGT_SRC) {
			addrptr = &iph->saddr;
		} else if (i == RANDMAP_MGT_DST) {
			addrptr = &iph->daddr;
		} else {
			WARN_ONCE(1, "randmap: nf_nat_ipv4_manip_pkt: invalid mangle type %d\n", i);
			addrptr = NULL;
		}

		if (addrptr != NULL) {
			if ((ctx->mangle_flags[i] & RANDMAP_MANGLE_IP) != 0) {
				newaddr = ctx->mangled[i].addr.ip;
				csum_replace4(&iph->check, *addrptr, newaddr);
				*addrptr = newaddr;
			}
		}
	}

	return true;
}

static bool nf_nat_ipv6_manip_pkt(struct sk_buff *skb, unsigned int iphdroff, struct randmap_mangle_context *ctx)
{
#if IS_ENABLED(CONFIG_IPV6)
	struct ipv6hdr *ipv6h;
	__be16 frag_off;
	int hdroff;
	u8 nexthdr;
	struct in6_addr *addrptr;
	unsigned int i;

	if (skb->len < iphdroff + sizeof(*ipv6h))
		return false;

	if (skb_ensure_writable(skb, iphdroff + sizeof(*ipv6h)))
		return false;

	ipv6h = (void *)skb->data + iphdroff;
	nexthdr = ipv6h->nexthdr;
	hdroff = ipv6_skip_exthdr(skb, iphdroff + sizeof(*ipv6h),
				  &nexthdr, &frag_off);
	if (hdroff < 0)
		goto manip_addr;

	ctx->l4proto = nexthdr;

	if ((frag_off & htons(~0x7)) == 0 &&
	    !l4proto_manip_pkt(skb, hdroff, ctx))
		return false;

	/* must reload, offset might have changed */
	ipv6h = (void *)skb->data + iphdroff;

manip_addr:
	for (i = 0; i < RANDMAP_MGT_MAX; i++) {
		if (i == RANDMAP_MGT_SRC) {
			addrptr = &ipv6h->saddr;
		} else if (i == RANDMAP_MGT_DST) {
			addrptr = &ipv6h->daddr;
		} else {
			WARN_ONCE(1, "randmap: nf_nat_ipv4_manip_pkt: invalid mangle type %d\n", i);
			addrptr = NULL;
		}

		if (addrptr != NULL) {
			if ((ctx->mangle_flags[i] & RANDMAP_MANGLE_IP) != 0) {
				*addrptr = ctx->mangled[i].addr.in6;
			}
		}
	}

#endif
	return true;
}

static void nf_nat_ipv4_csum_update(struct sk_buff *skb, __sum16 *check, const struct randmap_mangle_context *ctx)
{
	__be32 oldip, newip;
	unsigned int i;

	for (i = 0; i < RANDMAP_MGT_MAX; i++) {
		if ((ctx->mangle_flags[i] & RANDMAP_MANGLE_IP) != 0) {
			oldip = ctx->origin[i].addr.ip;
			newip = ctx->mangled[i].addr.ip;

			inet_proto_csum_replace4(check, skb, oldip, newip, true);
		}
	}
}

static void nf_nat_ipv6_csum_update(struct sk_buff *skb, __sum16 *check, const struct randmap_mangle_context *ctx)
{
#if IS_ENABLED(CONFIG_IPV6)
	const struct in6_addr *oldip, *newip;
	unsigned int i;

	for (i = 0; i < RANDMAP_MGT_MAX; i++) {
		if ((ctx->mangle_flags[i] & RANDMAP_MANGLE_IP) != 0) {
			oldip = &ctx->origin[i].addr.in6;
			newip = &ctx->mangled[i].addr.in6;

			inet_proto_csum_replace16(check, skb, oldip->s6_addr32, newip->s6_addr32, true);
		}
	}
#endif
}

static void nf_csum_update(struct sk_buff *skb, __sum16 *check, const struct randmap_mangle_context *ctx)
{
	switch (ctx->l3family) {
	case RANDMAP_L3FAMILY_IP4:
		nf_nat_ipv4_csum_update(skb, check, ctx);
		return;
	case RANDMAP_L3FAMILY_IP6:
		nf_nat_ipv6_csum_update(skb, check, ctx);
		return;
	}
}
