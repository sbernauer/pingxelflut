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
#include <sys/mman.h>

#include "bpf_util.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define WIDTH 1280
#define HEIGHT 720

struct framebuffer {
	int data[WIDTH * HEIGHT];
};

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
static void poll_stats(int map_fd, int interval)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	__u64 values[nr_cpus], prev[UINT8_MAX] = { 0 };
	int i;

	while (1) {
		__u32 key = UINT32_MAX;

		sleep(interval / 10);

		while (bpf_map_get_next_key(map_fd, &key, &key) != -1) {
			__u64 sum = 0;

			assert(bpf_map_lookup_elem(map_fd, &key, values) == 0);
			for (i = 0; i < nr_cpus; i++)
				sum += values[i];
			if (sum > prev[key])
				printf("proto %u: %10llu pkt/s\n",
				       key, (sum - prev[key]) / interval);
			prev[key] = sum;
		}
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
	printf("Hello world\n");

	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type	= BPF_PROG_TYPE_XDP,
	};
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	const char *optstr = "FSN";
	int prog_fd, map_fd, opt;
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
	map_fd = bpf_map__fd(map);

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

	// poll_stats(map_fd, 2);
	int size = sizeof(struct framebuffer);
	size = getpagesize();
	printf("size: %u\n", size);
	struct framebuffer* foo;
	foo = mmap(NULL, size, PROT_READ, MAP_SHARED, map_fd, 0);
	if (foo == MAP_FAILED) {
		printf("[ERROR] mmap failed: %d\n", errno);
		return -1;
	}
//	bss_mmaped = mmap(NULL, bss_sz, PROT_READ | PROT_WRITE, MAP_SHARED,
//			  bpf_map__fd(bss_map), 0);
//	if (CHECK(bss_mmaped == MAP_FAILED, "bss_mmap",
//		  ".bss mmap failed: %d\n", errno)) {
//		bss_mmaped = NULL;
//		goto cleanup;
//	}

	// if(fcntl(map_fd, map_fd) != -1 || errno != EBADF) {
	// 	printf("Valid filedescriptor\n");
	// }

	for(int i = 0; i < 50; i++) {
		int index = 0;
		int value;

		//int foo_value = *foo;
		for (int i = 0; i < 10; i++) {
			index = i;
			bpf_map_lookup_elem(map_fd, &index, &value);
			printf("value via bpf_map_lookup_elem for %u: %0x\n", i, value);
			printf("value via mmap for %u:                %0x\n", i, foo->data[i]);
		}
		for (int i = WIDTH * HEIGHT - 10; i < WIDTH * HEIGHT; i++) {
			printf("value via mmap for %u:                %0x\n", i, foo->data[i]);
		}
		printf("\n");

		sleep(1);
	}

	return 0;
}
