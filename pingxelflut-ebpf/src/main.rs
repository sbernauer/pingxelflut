#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{
    bindings::{
        xdp_action::{XDP_ABORTED, XDP_DROP, XDP_PASS},
        BPF_F_MMAPABLE,
    },
    macros::{map, xdp},
    maps::Array,
    programs::XdpContext,
};
// We always need this import, so that the log event array AYA_LOGS always exists
#[allow(unused_imports)]
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    icmp::IcmpHdr,
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
};

use pingxelflut_common::{CANVAS_HEIGHT, CANVAS_PIXELS, CANVAS_WIDTH};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[map]
static FRAMEBUFFER: Array<u32> = Array::with_max_entries(CANVAS_PIXELS, BPF_F_MMAPABLE);

#[xdp]
pub fn pingxelflut(ctx: XdpContext) -> u32 {
    match try_pingxelflut(ctx) {
        Ok(ret) => ret,
        Err(_) => XDP_ABORTED,
    }
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[inline(always)]
fn try_pingxelflut(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;

    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {
            let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
            match unsafe { *ipv4hdr }.proto {
                IpProto::Icmp => {
                    let icmp_hdr: *const IcmpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                    return handle_icmpv4_pingxelflut(&ctx, icmp_hdr);
                }
                _ => {
                    return Ok(XDP_PASS);
                }
            }
        }
        EtherType::Ipv6 => {
            // TODO: Handle ICMP6 traffic
        }
        _ => {
            return Ok(XDP_DROP);
        }
    }

    let ipv6hdr: *const Ipv6Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let dst = unsafe { (*ipv6hdr).dst_addr };

    let x = unsafe { dst.in6_u.u6_addr16.get_unchecked(4) }.to_be();
    let y = unsafe { dst.in6_u.u6_addr16.get_unchecked(5) }.to_be();
    let rgba = unsafe { dst.in6_u.u6_addr32.get_unchecked(3) }.to_be();

    info!(&ctx, "Got IPv6 with x {:x}, y {:x}, rgba {:x}", x, y, rgba);
    info!(&ctx, "Index: {}", x as u32 + y as u32 * CANVAS_WIDTH as u32);

    set_pixel(&ctx, x, y, rgba);

    Ok(XDP_PASS)
}

#[inline(always)]
fn handle_icmpv4_pingxelflut(ctx: &XdpContext, icmp_hdr: *const IcmpHdr) -> Result<u32, ()> {
    const ICMP_TYPE_ECHO_REQUEST: u8 = 8;
    if (unsafe { *icmp_hdr }).type_ == ICMP_TYPE_ECHO_REQUEST && unsafe { *icmp_hdr }.code == 0 {
        let kind: u8 = unsafe { *ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN + IcmpHdr::LEN)? };
        match kind {
            0xaa => {
                // TODO: Handle size requests
            }
            0xbb => {
                // size responses can be ignored
            }
            0xcc => {
                let x = u16::from_be_bytes(unsafe {
                    *ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN + IcmpHdr::LEN + 1)?
                });
                let y = u16::from_be_bytes(unsafe {
                    *ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN + IcmpHdr::LEN + 3)?
                });
                let rgba = u32::from_be_bytes(unsafe {
                    *ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN + IcmpHdr::LEN + 5)?
                });
                // info!(
                //     ctx,
                //     "Detected ICMP echo request packet with x: {}, y: {}, rgba: {}", x, y, rgba
                // );
                set_pixel(&ctx, x, y, rgba);
            }
            _ => {}
        }
    }

    Ok(XDP_DROP)
}

#[inline(always)]
fn set_pixel(_ctx: &XdpContext, x: u16, y: u16, rgba: u32) {
    if x >= CANVAS_WIDTH || y >= CANVAS_HEIGHT {
        return;
    }

    if let Some(ptr) = FRAMEBUFFER.get_ptr_mut(x as u32 + y as u32 * CANVAS_WIDTH as u32) {
        // TODO: Handle alpha channel (if desired). Currently we just insert as-is for maximum performance, so it's the
        // responsibility of the userspace to ignore the alpha bits.
        unsafe { *ptr = rgba };
    }
}
