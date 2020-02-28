#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>

#define WIDTH 1280
#define HEIGHT 720

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, WIDTH * HEIGHT);
    __uint(map_flags, BPF_F_MMAPABLE); // Needed to mmap this map later on in userspace
} framebuffer SEC(".maps");

// Returns 0 if successfull. Returns XDP_DROP, if packet was malformed.
static inline int process_ipv6_packet(void *data, u64 nh_off, void *data_end)
{
    struct ipv6hdr *ip6h = data + nh_off;
    struct in6_addr dst_addr;
    void* pointToStartOfIp6;

    u16 x, y;
    u32 rgb, index;

    if (unlikely(ip6h + 1 > data_end)) // Is needed because of verifier
        return XDP_DROP;

    dst_addr = ip6h->daddr;
    pointToStartOfIp6 = &dst_addr;

    x = (*((u8 *)(pointToStartOfIp6 + 8)) << 8) | (*((u8 *)(pointToStartOfIp6 + 9))); // Flip the first to byte, format is now left to right 00 00 ll hh, attention: byte order is opposite direction whe looking with 'bpftool map dump'
    y = (*((u8 *)(pointToStartOfIp6 + 10)) << 8) | (*((u8 *)(pointToStartOfIp6 + 11))); // Same as x
    rgb = (*((u8 *)(pointToStartOfIp6 + 12)) << 24) | (*((u8 *)(pointToStartOfIp6 + 13)) << 16) | (*((u8 *)(pointToStartOfIp6 + 14)) << 8); // Ignore last part of rrggbb>>>padding<<< | (*((u8 *)(pointToStartOfIp6 + 15)));

    if (x >= WIDTH || y >= HEIGHT)
        return XDP_DROP;
    index = x + y * WIDTH;
    bpf_map_update_elem(&framebuffer, &index, &rgb, BPF_ANY);

    return 0;
}

SEC("xdp_pingxelflut")
int xdp_prog_pingxelflut(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct ipv6hdr *ip6h;
    u16 h_proto;
    u64 nh_off;
    int ret;

    nh_off = sizeof(*eth);
    if (unlikely(data + nh_off > data_end)) // Needed because of verifier
        return XDP_DROP;

    h_proto = eth->h_proto;
    if (h_proto == htons(ETH_P_IPV6)) {
        ret = process_ipv6_packet(data, nh_off, data_end);
        if (ret != 0)
            return ret;
    } else if (h_proto == htons(ETH_P_IPV6) || h_proto == htons(ETH_P_IPV6)) { // VLAN or Link aggregation
        struct vlan_hdr *vhdr;

        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);
        if (data + nh_off > data_end) // Needed because of verifier
            return XDP_DROP;

        h_proto = vhdr->h_vlan_encapsulated_proto;
        if (h_proto == htons(ETH_P_IPV6)) {
            ret = process_ipv6_packet(data, nh_off, data_end);
            if (ret != 0)
                return ret;
        }
    }

    return XDP_PASS; // Change it to XDP_DOP to get maximum performance
}

char _license[] SEC("license") = "GPL";
