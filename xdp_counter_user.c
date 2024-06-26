// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2016 PLUMgrid
 */
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/resource.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "bpf_util.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

static int ifindex;
static __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
static __u32 prog_id;

static void int_exit(int sig)
{
	__u32 curr_prog_id = 0;

	if (bpf_get_link_xdp_id(ifindex, &curr_prog_id, xdp_flags)) {
		printf("bpf_get_link_xdp_id failed\n");
		exit(1);
	}
	if (prog_id == curr_prog_id)
		bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
	else if (!curr_prog_id)
		printf("couldn't find a prog id on a given interface\n");
	else
		printf("program on interface changed, not removing\n");
	exit(0);
}

/* simple per-protocol drop counter
 */
static void poll_stats(int map_fd_ipv4, int map_fd_ipv6, char* iface_name, int interval)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	__u64 values[nr_cpus];
	__u64 sum = 0;
	int i;
	char str_ipv4[INET_ADDRSTRLEN];
	char str_ipv6[INET_ADDRSTRLEN];

	while (1) {
		printf("\e[1;1H\e[2J");
		printf("Counting destination IP-Addresses of all IP packets on interface %s\n\n", iface_name);
		printf("|== IPv4 =================================|===================|\n");
		__u32 key_ipv4 = UINT32_MAX;
		while (bpf_map_get_next_key(map_fd_ipv4, &key_ipv4, &key_ipv4) != -1) {
			sum = 0;

			assert(bpf_map_lookup_elem(map_fd_ipv4, &key_ipv4, values) == 0);
			for (i = 0; i < nr_cpus; i++) {
				sum += values[i];
				values[i] = 0;
			}
			bpf_map_update_elem(map_fd_ipv4, &key_ipv4, values, BPF_ANY);
			inet_ntop(AF_INET, &key_ipv4, str_ipv4, INET_ADDRSTRLEN);
			printf("| %39s | %10llu pkts/s |\n", str_ipv4, sum); // 8 * 4 + 7 = max 39 digits for Ipv6 address
		}

		printf("|== IPv6 =================================|===================|\n");
		struct in6_addr key_ipv6;
		memset(&key_ipv6, 0xff, sizeof(key_ipv6));
		while (bpf_map_get_next_key(map_fd_ipv6, &key_ipv6, &key_ipv6) != -1) {
			sum = 0;

			assert(bpf_map_lookup_elem(map_fd_ipv6, &key_ipv6, values) == 0);
			for (i = 0; i < nr_cpus; i++) {
				sum += values[i];
				values[i] = 0;
			}
			bpf_map_update_elem(map_fd_ipv6, &key_ipv6, values, BPF_ANY);
			inet_ntop(AF_INET6, &key_ipv6, str_ipv6, INET6_ADDRSTRLEN);
			printf("| %39s | %10llu pkts/s |\n", str_ipv6, sum);
		}
		printf("|=========================================|===================|\n");


		sleep(interval);
	}
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s [OPTS] IFACE\n\n"
		"OPTS:\n"
		"    -S    use skb-mode\n"
		"    -N    enforce native mode\n"
		"    -F    force loading prog\n",
		prog);
}

int main(int argc, char **argv)
{
	int cpus = bpf_num_possible_cpus();
	printf("Running on %u CPU cores\n", cpus);

	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type	= BPF_PROG_TYPE_XDP,
	};
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	const char *optstr = "FSN";
	int prog_fd, map_fd_ipv4, map_fd_ipv6, opt;
	struct bpf_object *obj;
	struct bpf_map *map;
	char filename[256];
	int err;

	while ((opt = getopt(argc, argv, optstr)) != -1) {
		switch (opt) {
		case 'S':
			xdp_flags |= XDP_FLAGS_SKB_MODE;
			break;
		case 'N':
			/* default, set below */
			break;
		case 'F':
			xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;
			break;
		default:
			usage(basename(argv[0]));
			return 1;
		}
	}

	if (!(xdp_flags & XDP_FLAGS_SKB_MODE))
		xdp_flags |= XDP_FLAGS_DRV_MODE;

	if (optind == argc) {
		usage(basename(argv[0]));
		return 1;
	}

	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		perror("setrlimit(RLIMIT_MEMLOCK)");
		return 1;
	}

	ifindex = if_nametoindex(argv[optind]);
	if (!ifindex) {
		perror("if_nametoindex");
		return 1;
	}

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
	prog_load_attr.file = filename;

	if (bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd))
		return 1;

	map = bpf_map__next(NULL, obj);
	if (!map) {
		printf("finding a map in obj file failed\n");
		return 1;
	}
	map_fd_ipv4 = bpf_map__fd(map);

	map = bpf_map__next(map, obj);
	if (!map) {
		printf("finding a map in obj file failed\n");
		return 1;
	}
	map_fd_ipv6 = bpf_map__fd(map);

	if (!prog_fd) {
		printf("bpf_prog_load_xattr: %s\n", strerror(errno));
		return 1;
	}

	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);

	if (bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags) < 0) {
		printf("link set xdp fd failed\n");
		return 1;
	}

	err = bpf_obj_get_info_by_fd(prog_fd, &info, &info_len);
	if (err) {
		printf("can't get prog info - %s\n", strerror(errno));
		return err;
	}
	prog_id = info.id;

	poll_stats(map_fd_ipv4, map_fd_ipv6, argv[optind], 1);

	return 0;
}
