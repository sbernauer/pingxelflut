#!/bin/bash

# pacman -S make clang llvm base-devel flex bison bc python

num_cpus=$(nproc --all)

# Build pingxelflut
## Build linux BPF samples
if [[ -d linux ]]; then
	echo "Skipped cloning and building/preparing of linux kernel source"
else
	git clone --depth 10 https://github.com/torvalds/linux

	cd linux
	make -j $num_cpus allyesconfig
	make -j $num_cpus prepare
	make -j $num_cpus headers_install

	cd samples/bpf
	make

	# Build helper tools
	## Build bpftool
	cd ../../tools/bpf/bpftool
	make -j $num_cpus
	cd ../../../..
fi

## Copy pingxelflut to linux kernel source
cp xdp_pingxelflut_kern.c xdp_pingxelflut_user.c linux/samples/bpf
sed -i -e 's/tprogs-y += xdp1/tprogs-y += xdp_pingxelflut\ntprogs-y += xdp1/' linux/samples/bpf/Makefile
sed -i -e 's/xdp1-objs := xdp1_user.o/xdp_pingxelflut-objs := xdp_pingxelflut_user.o\nxdp1-objs := xdp1_user.o/' linux/samples/bpf/Makefile
sed -i -e 's/always-y += xdp1_kern.o/always-y += xdp_pingxelflut_kern.o\nalways-y += xdp1_kern.o/' linux/samples/bpf/Makefile

## Copy counter to linux kernel source
cp xdp_counter_kern.c xdp_counter_user.c linux/samples/bpf
sed -i -e 's/tprogs-y += xdp1/tprogs-y += xdp_counter\ntprogs-y += xdp1/' linux/samples/bpf/Makefile
sed -i -e 's/xdp1-objs := xdp1_user.o/xdp_counter-objs := xdp_counter_user.o\nxdp1-objs := xdp1_user.o/' linux/samples/bpf/Makefile
sed -i -e 's/always-y += xdp1_kern.o/always-y += xdp_counter_kern.o\nalways-y += xdp1_kern.o/' linux/samples/bpf/Makefile

## Build pingxelflut kernel and userspace programs
cd linux/samples/bpf
make -j $num_cpus
