#!/bin/bash

# Build pingxelflut
## Build linux BPF samples
git clone --depth 10 https://github.com/torvalds/linux

cd linux
make allyesconfig
make prepare
make headers_install

cd samples/bpf
make

## Copy pingxelflut to linux kernel source
cd ../../..
cp xdp_pingxelflut_kern.c xdp_pingxelflut_user.c linux/samples/bpf

## Add new pingxelflut to Makefile
cd linux/samples/bpf
sed -i -e 's/tprogs-y += xdp1/tprogs-y += xdp_pingxelflut\ntprogs-y += xdp1/' Makefile
sed -i -e 's/xdp1-objs := xdp1_user.o/xdp_pingxelflut-objs := xdp_pingxelflut_user.o\nxdp1-objs := xdp1_user.o/' Makefile
sed -i -e 's/always-y += xdp1_kern.o/always-y += xdp_pingxelflut_kern.o\nalways-y += xdp1_kern.o/' Makefile

## Build pingxelflut kernel and userspace programs
make

# Build helper tools
## Build bpftool
cd ../../..
cd linux/tools/bpf/bpftool
make