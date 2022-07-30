// SPDX-License-Identifier: GPL-2.0-only
/* (C) 2022 Haruue Icymoon <i@haruue.moe>
 */

#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <xtables.h>

#include <randmap/xt_randmap.h>

#define MODULENAME "RANDMAP"

enum {
	O_SRC = 0,
	O_SPORT = 1,
	O_DST = 2,
	O_DPORT = 3,
};

static const struct xt_option_entry RANDMAP_opts[] = {
	{ .name = "src-pfx",	.id = O_SRC,	.type = XTTYPE_HOSTMASK },
	{ .name = "sport",	.id = O_SPORT,	.type = XTTYPE_PORTRC },
	{ .name = "dst-pfx",	.id = O_DST,	.type = XTTYPE_HOSTMASK },
	{ .name = "dport",	.id = O_DPORT, 	.type = XTTYPE_PORTRC },
	XTOPT_TABLEEND
};

static void RANDMAP_help(void)
{
	printf(MODULENAME" target options:\n"
		   "  --%s prefix/length\n"
		   "                                Prefix for random source address.\n\n"
		   "  --%s port:port\n"
		   "                                Port range for random source port.\n\n"
		   "  --%s prefix/length\n"
		   "                                Prefix for random destination address.\n\n"
		   "  --%s port:port\n"
		   "                                Port range for random destination port.\n\n",
		   RANDMAP_opts[0].name,
		   RANDMAP_opts[1].name,
		   RANDMAP_opts[2].name,
		   RANDMAP_opts[3].name);
}

static void __RANDMAP_print_cidr(const struct randmap_mangle_range *rmr, uint16_t family)
{
	switch (family) {
		case NFPROTO_IPV4:
			printf("%s/%u",
				   xtables_ipaddr_to_numeric(&rmr->net.in),
				   xtables_ipmask_to_cidr(&rmr->mask.in));
			break;
		case NFPROTO_IPV6:
			printf("%s/%u",
				   xtables_ip6addr_to_numeric(&rmr->net.in6),
				   xtables_ip6mask_to_cidr(&rmr->mask.in6));
			break;
		default:
			printf("[error: unknown family %d]", family);
			break;
	}
}

static void __RANDMAP_print_port_range(const struct randmap_mangle_range *rmr)
{
	printf("%u:%u", rmr->min_proto, rmr->max_proto);
}

static void __RANDMAP_print_generic(const struct xt_entry_target *target, const char *fmt, uint16_t family)
{
	const struct randmap_info *info = (const void *) target->data;

	if ((info->ranges[RANDMAP_MGT_SRC].flags & RANDMAP_MANGLE_IP) != 0) {
		printf(fmt, RANDMAP_opts[0].name);
		__RANDMAP_print_cidr(&info->ranges[RANDMAP_MGT_SRC], family);
	}

	if ((info->ranges[RANDMAP_MGT_SRC].flags & RANDMAP_MANGLE_PROTO) != 0) {
		printf(fmt, RANDMAP_opts[1].name);
		__RANDMAP_print_port_range(&info->ranges[RANDMAP_MGT_SRC]);
	}

	if ((info->ranges[RANDMAP_MGT_DST].flags & RANDMAP_MANGLE_IP) != 0) {
		printf(fmt, RANDMAP_opts[2].name);
		__RANDMAP_print_cidr(&info->ranges[RANDMAP_MGT_DST], family);
	}

	if ((info->ranges[RANDMAP_MGT_DST].flags & RANDMAP_MANGLE_PROTO) != 0) {
		printf(fmt, RANDMAP_opts[3].name);
		__RANDMAP_print_port_range(&info->ranges[RANDMAP_MGT_DST]);
	}
}

static void __RANDMAP_print(const struct xt_entry_target *target, uint16_t family)
{
	__RANDMAP_print_generic(target, " %s:", family);
}

static void __RANDMAP_save(const struct xt_entry_target *target, uint16_t family)
{
	__RANDMAP_print_generic(target, " --%s ", family);
}

static void RANDMAP_print4(const void *ip, const struct xt_entry_target *target, int numeric)
{
	__RANDMAP_print(target, NFPROTO_IPV4);
}

static void RANDMAP_save4(const void *ip, const struct xt_entry_target *target)
{
	__RANDMAP_save(target, NFPROTO_IPV4);
}

static void RANDMAP_print6(const void *ip, const struct xt_entry_target *target, int numeric)
{
	__RANDMAP_print(target, NFPROTO_IPV6);
}

static void RANDMAP_save6(const void *ip, const struct xt_entry_target *target)
{
	__RANDMAP_save(target, NFPROTO_IPV6);
}

static void RANDMAP_parse(struct xt_option_call *cb)
{
	struct randmap_info *info = cb->data;

	xtables_option_parse(cb);
	switch (cb->entry->id) {
		case O_SRC:
			info->ranges[RANDMAP_MGT_SRC].flags |= RANDMAP_MANGLE_IP;
			info->ranges[RANDMAP_MGT_SRC].net.in6 = cb->val.haddr.in6;
			info->ranges[RANDMAP_MGT_SRC].mask.in6 = cb->val.hmask.in6;
			break;
		case O_SPORT:
			info->ranges[RANDMAP_MGT_SRC].flags |= RANDMAP_MANGLE_PROTO;
			info->ranges[RANDMAP_MGT_SRC].min_proto = cb->val.port_range[0];
			info->ranges[RANDMAP_MGT_SRC].max_proto = cb->val.port_range[1];
			break;
		case O_DST:
			info->ranges[RANDMAP_MGT_DST].flags |= RANDMAP_MANGLE_IP;
			info->ranges[RANDMAP_MGT_DST].net.in6 = cb->val.haddr.in6;
			info->ranges[RANDMAP_MGT_DST].mask.in6 = cb->val.hmask.in6;
			break;
		case O_DPORT:
			info->ranges[RANDMAP_MGT_DST].flags |= RANDMAP_MANGLE_PROTO;
			info->ranges[RANDMAP_MGT_DST].min_proto = cb->val.port_range[0];
			info->ranges[RANDMAP_MGT_DST].max_proto = cb->val.port_range[1];
			break;
	}
}

static struct xtables_target randmap_tg_regs[] = {
	{
		.name			= MODULENAME,
		.version		= XTABLES_VERSION,
		.family			= NFPROTO_IPV4,
		.size			= XT_ALIGN(sizeof(struct randmap_info)),
		.userspacesize	= XT_ALIGN(sizeof(struct randmap_info)),
		.help			= RANDMAP_help,
		.print			= RANDMAP_print4,
		.save			= RANDMAP_save4,
		.x6_options     = RANDMAP_opts,
		.x6_parse       = RANDMAP_parse,
	},
	{
		.name			= MODULENAME,
		.version		= XTABLES_VERSION,
		.family			= NFPROTO_IPV6,
		.size			= XT_ALIGN(sizeof(struct randmap_info)),
		.userspacesize	= XT_ALIGN(sizeof(struct randmap_info)),
		.help			= RANDMAP_help,
		.print			= RANDMAP_print6,
		.save			= RANDMAP_save6,
		.x6_options     = RANDMAP_opts,
		.x6_parse       = RANDMAP_parse,
	},
};


void _init(void)
{
	xtables_register_targets(randmap_tg_regs, sizeof(randmap_tg_regs) / sizeof(randmap_tg_regs[0]));
}