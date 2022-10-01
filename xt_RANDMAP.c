// SPDX-License-Identifier: GPL-2.0-only
/* (C) 2022 Haruue Icymoon <i@haruue.moe>
 */

#include <randmap/xt_randmap.h>

#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/ipv6.h>
#include <linux/random.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/netfilter/x_tables.h>

#include "nf_nat_proto.inc"

static unsigned int
randmap_tg6(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct randmap_info *info;
	struct randmap_mangle_context ctx;
	unsigned int i, j;
	__u16 randomized_port;

	info = par->targinfo;

	ctx.mangle_flags[RANDMAP_MGT_SRC] = info->ranges[RANDMAP_MGT_SRC].flags;
	ctx.mangle_flags[RANDMAP_MGT_DST] = info->ranges[RANDMAP_MGT_DST].flags;

	ctx.l3family = RANDMAP_L3FAMILY_IP6;
	ctx.origin[RANDMAP_MGT_SRC].addr.in6 = ipv6_hdr(skb)->saddr;
	ctx.origin[RANDMAP_MGT_DST].addr.in6 = ipv6_hdr(skb)->daddr;

	// l4 proto will be handled later, we only care about l3 now.

	for (i = 0; i < RANDMAP_MGT_MAX; i++) {
		if ((ctx.mangle_flags[i] & RANDMAP_MANGLE_IP) != 0) {
			get_random_bytes(ctx.mangled[i].addr.ip6, sizeof(ctx.mangled[i].addr.ip6));
			for (j = 0; j < ARRAY_SIZE(ctx.mangled[i].addr.ip6); j++) {
				ctx.mangled[i].addr.ip6[j] &= ~info->ranges[i].mask.ip6[j];
				ctx.mangled[i].addr.ip6[j] |= info->ranges[i].net.ip6[j] & info->ranges[i].mask.ip6[j];
			}
		}
		if ((ctx.mangle_flags[i] & RANDMAP_MANGLE_PROTO) != 0) {
			randomized_port = info->ranges[i].min_proto;
			randomized_port += get_random_int() % (info->ranges[i].max_proto - info->ranges[i].min_proto + 1);
			ctx.mangled[i].proto.all = htons(randomized_port);
		}
	}

	nf_nat_ipv6_manip_pkt(skb, 0, &ctx);

	return XT_CONTINUE;
}

static int randmap_tg6_checkentry(const struct xt_tgchk_param *par)
{
	const struct randmap_info *info = par->targinfo;

	// TODO: perform check
	(void) info;

	return 0;
}

static unsigned int
randmap_tg4(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct randmap_info *info;
	struct randmap_mangle_context ctx;
	unsigned int i;

	info = par->targinfo;

	ctx.mangle_flags[RANDMAP_MGT_SRC] = info->ranges[RANDMAP_MGT_SRC].flags;
	ctx.mangle_flags[RANDMAP_MGT_DST] = info->ranges[RANDMAP_MGT_DST].flags;

	ctx.l3family = RANDMAP_L3FAMILY_IP4;
	ctx.origin[RANDMAP_MGT_SRC].addr.ip = ip_hdr(skb)->saddr;
	ctx.origin[RANDMAP_MGT_DST].addr.ip = ip_hdr(skb)->daddr;

	// l4 proto will be handled later, we only care about l3 now.

	for (i = 0; i < RANDMAP_MGT_MAX; i++) {
		if ((ctx.mangle_flags[i] & RANDMAP_MANGLE_IP) != 0) {
			ctx.mangled[i].addr.ip = get_random_u32();
			ctx.mangled[i].addr.ip &= ~info->ranges[i].mask.ip;
			ctx.mangled[i].addr.ip |= info->ranges[i].net.ip & info->ranges[i].mask.ip;
		}
		if ((ctx.mangle_flags[i] & RANDMAP_MANGLE_PROTO) != 0) {
			ctx.mangled[i].proto.all = info->ranges[i].min_proto;
			ctx.mangled[i].proto.all += get_random_int() % (info->ranges[i].max_proto - info->ranges[i].min_proto + 1);
			ctx.mangled[i].proto.all = htons(ctx.mangled[i].proto.all);
		}
	}

	nf_nat_ipv4_manip_pkt(skb, 0, &ctx);

	return XT_CONTINUE;
}

static int randmap_tg4_check(const struct xt_tgchk_param *par)
{
	const struct randmap_info *info = par->targinfo;

	// TODO: perform check
	(void) info;

	return 0;
}

static struct xt_target randmap_tg_reg[] __read_mostly = {
	{
		.name		= "RANDMAP",
		.family		= NFPROTO_IPV4,
		.revision	= 0,
		.target		= randmap_tg4,
		.targetsize	= sizeof(struct randmap_info),
		.table		= "mangle",
		.hooks		= (1 << NF_INET_PRE_ROUTING) |
					  (1 << NF_INET_POST_ROUTING) |
					  (1 << NF_INET_LOCAL_OUT) |
					  (1 << NF_INET_LOCAL_IN),
		.checkentry	= randmap_tg4_check,
		.me			= THIS_MODULE,
	},
	{
		.name		= "RANDMAP",
		.family		= NFPROTO_IPV6,
		.revision   = 0,
		.target		= randmap_tg6,
		.targetsize	= sizeof(struct randmap_info),
		.table		= "mangle",
		.hooks		= (1 << NF_INET_PRE_ROUTING) |
				      (1 << NF_INET_POST_ROUTING) |
					  (1 << NF_INET_LOCAL_OUT) |
					  (1 << NF_INET_LOCAL_IN),
		.checkentry	= randmap_tg6_checkentry,
		.me			= THIS_MODULE,
	},
};

static int __init randmap_tg_init(void)
{
	return xt_register_targets(randmap_tg_reg, ARRAY_SIZE(randmap_tg_reg));
}

static void randmap_tg_exit(void)
{
	xt_unregister_targets(randmap_tg_reg, ARRAY_SIZE(randmap_tg_reg));
}

module_init(randmap_tg_init);
module_exit(randmap_tg_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("RANDMAP: stateless address/port randomization for IPv4/v6 packets");
MODULE_AUTHOR("Haruue Icymoon <i@haruue.moe>");
MODULE_ALIAS("ip6t_RANDMAP");
MODULE_ALIAS("ipt_RANDMAP");
