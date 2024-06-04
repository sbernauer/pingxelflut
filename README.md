# pingxelflut

## Prerequisites

1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

## Build Userspace

```bash
cargo build
```

## Build eBPF and Userspace

```bash
cargo xtask build
```

## Run

```bash
RUST_LOG=info cargo xtask run
```


## Test using loopback interface
There might be a better solution to route ::/64 to lo but I couldn't get it to work.

```bash
ip a s dev lo
ip -6 r s dev lo

sudo ip a a 2000::1:0:0:1/64 dev lo
sudo ip a a 2000::0:0:1234:5600/64 dev lo
sudo ip a a 2000::0:1:1234:5600/64 dev lo
sudo ip a a 2000::1:0:1234:5600/64 dev lo
sudo ip a a 2000::1:1:1234:5600/64 dev lo
sudo ip a a 2000::2:0:1234:5600/64 dev lo
sudo ip a a 2000::2:1:1234:5600/64 dev lo
sudo ip a a 2000::3:0:1234:5600/64 dev lo
sudo ip a a 2000::3:1:1234:5600/64 dev lo
sudo ip a a 2000::4:0:1234:5600/64 dev lo
sudo ip a a 2000::4:4:1234:5600/64 dev lo
sudo ip a a 2000::5:0:1234:5600/64 dev lo
sudo ip a a 2000::5:1:1234:5600/64 dev lo
# (1919, 1079)
sudo ip a a 2000::077f:0437:1234:5600/64 dev lo
```
