/* Copyright (c) 2016 PLUMgrid
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>

struct bpf_map_def SEC("maps") rxcnt_ipv4 = {
        .type = BPF_MAP_TYPE_PERCPU_HASH,
        .key_size = sizeof(u32),
        .value_size = sizeof(long),
        .max_entries = 1000000,
};

struct bpf_map_def SEC("maps") rxcnt_ipv6 = {
        .type = BPF_MAP_TYPE_PERCPU_HASH,
        .key_size = sizeof(struct in6_addr),
        .value_size = sizeof(long),
        .max_entries = 1000000,
};

static int parse_ipv4(void *data, u64 nh_off, void *data_end)
{
	struct iphdr *iph = data + nh_off;

	if (iph + 1 > data_end)
		return 0;
	return iph->protocol;
}

static int parse_ipv6(void *data, u64 nh_off, void *data_end)
{
	struct ipv6hdr *ip6h = data + nh_off;

	if (ip6h + 1 > data_end)
		return 0;
	return ip6h->nexthdr;
}

SEC("xdp_counter")
int xdp_prog_counter(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	int rc = XDP_PASS;
	long *value;
	u16 h_proto;
	u64 nh_off;
	u32 ipproto;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return rc;

	h_proto = eth->h_proto;

	if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
		struct vlan_hdr *vhdr;

		vhdr = data + nh_off;
		nh_off += sizeof(struct vlan_hdr);
		if (data + nh_off > data_end)
			return rc;
		h_proto = vhdr->h_vlan_encapsulated_proto;
	}
	if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
		struct vlan_hdr *vhdr;

		vhdr = data + nh_off;
		nh_off += sizeof(struct vlan_hdr);
		if (data + nh_off > data_end)
			return rc;
		h_proto = vhdr->h_vlan_encapsulated_proto;
	}

	if (h_proto == htons(ETH_P_IP)) {
		struct iphdr *iph = data + nh_off;

		if (iph + 1 > data_end)
			return rc;
		ipproto = iph->protocol;
		u32 daddr = iph->daddr;

		value = bpf_map_lookup_elem(&rxcnt_ipv4, &daddr);
		if (value) {
			*value += 1;
		} else {
			long new = 1;
			bpf_map_update_elem(&rxcnt_ipv4, &daddr, &new, BPF_ANY);
		}
	} else if (h_proto == htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6h = data + nh_off;

		if (ip6h + 1 > data_end)
			return rc;
		ipproto = ip6h->nexthdr;
		struct in6_addr daddr = ip6h->daddr;

		value = bpf_map_lookup_elem(&rxcnt_ipv6, &daddr);
		if (value) {
			*value += 1;
		} else {
			long new = 1;
			bpf_map_update_elem(&rxcnt_ipv6, &daddr, &new, BPF_ANY);
		}
	}

	return rc;
}

char _license[] SEC("license") = "GPL";
