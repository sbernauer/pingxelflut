# pingxelflut
Pingxelflut (Pixelflut v6) client using ebpf programms.
With this technique parts of this software run directly in the kernel and thus provide very fast packet processing.
The software is splitted in two parts:

Kernel:

The bpf-program allocates an bpf-map, which acts an an framebuffer. It inspects every packet received on an interface. If it is an IPv6-packet, it is interpreted as an pingxelflut packet and the corresponding pixel on the framebuffer is colored.

Userspace:

The userspace cyclical reads from the framebuffer and displays the pixels (for example copies the content to a vnc-server). To be efficient (not to do a syscall for every pixel with bpf_map_lookup_elem!!) the bpf-map is mmaped and accessed directly. Therefore a kernel >= 5.5 is needed!
