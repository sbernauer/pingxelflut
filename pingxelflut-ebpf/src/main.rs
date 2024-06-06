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
use aya_log_ebpf::{info, warn};
use network_types::{
    eth::{EthHdr, EtherType},
    icmp::IcmpHdr,
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
};

use pingxelflut_common::{
    CANVAS_HEIGHT, CANVAS_PIXELS, CANVAS_WIDTH, ICMP_TYPE_ECHO_REQUEST, MSG_GET_SIZE_REQUEST,
    MSG_SET_PIXEL, MSG_SIZE_RESPONSE,
};

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
fn mut_ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let ptr: *const T = ptr_at(ctx, offset)?;
    Ok(ptr as *mut T)
}

#[inline(always)]
fn try_pingxelflut(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *mut EthHdr = mut_ptr_at(&ctx, 0)?;

    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {
            let ipv4hdr: *mut Ipv4Hdr = mut_ptr_at(&ctx, EthHdr::LEN)?;
            match unsafe { (*ipv4hdr).proto } {
                IpProto::Icmp => {
                    let icmp_hdr: *mut IcmpHdr = mut_ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                    return unsafe { handle_icmpv4_pingxelflut(&ctx, ethhdr, ipv4hdr, icmp_hdr) };
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
            return Ok(XDP_PASS);
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
unsafe fn handle_icmpv4_pingxelflut(
    ctx: &XdpContext,
    ethhdr: *mut EthHdr,
    ipv4hdr: *mut Ipv4Hdr,
    icmp_hdr: *mut IcmpHdr,
) -> Result<u32, ()> {
    if (*icmp_hdr).type_ == ICMP_TYPE_ECHO_REQUEST && (*icmp_hdr).code == 0 {
        let icmp_data_len = ctx.data_end() - ctx.data() - EthHdr::LEN - Ipv4Hdr::LEN - IcmpHdr::LEN;
        let msg_kind: *mut u8 = mut_ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN + IcmpHdr::LEN)?;

        // This match is sorted descending by estimaed occourance of the command
        match *msg_kind {
            // Set pixel
            MSG_SET_PIXEL => {
                let x = u16::from_be_bytes(*ptr_at(
                    ctx,
                    EthHdr::LEN + Ipv4Hdr::LEN + IcmpHdr::LEN + 1,
                )?);
                let y = u16::from_be_bytes(*ptr_at(
                    ctx,
                    EthHdr::LEN + Ipv4Hdr::LEN + IcmpHdr::LEN + 3,
                )?);

                let remaining = icmp_data_len.wrapping_sub(5);

                // Only rgb
                if remaining == 3 {
                    // We read an u32 instead of u16 + u8 here (hopefully for performance reasons), but we read one
                    // byte on the left from the previous content
                    let xrgb = u32::from_be_bytes(*ptr_at(
                        ctx,
                        EthHdr::LEN + Ipv4Hdr::LEN + IcmpHdr::LEN + 4,
                    )?);
                    let rgb = xrgb << 8;
                    set_pixel(&ctx, x, y, rgb);
                    return Ok(XDP_DROP);

                // With alpha
                // We don't check for exact 4 here, so that clients can send longer than needed packages because
                // - why not?
                } else if remaining > 4 {
                    if let Some(rgba) = *ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN + IcmpHdr::LEN + 5)?
                    {
                        info!(ctx, "Read rgba");
                        set_pixel(&ctx, x, y, rgba);
                        return Ok(XDP_DROP);
                    }
                } else {
                    warn!(ctx, "Malformed packed - less than 3 remaining");
                    return Ok(XDP_DROP);
                }
            }
            MSG_GET_SIZE_REQUEST => {
                info!(
                    ctx,
                    "[SIZE] Received size request from {:i} ({:MAC}) to {:i} ({:MAC}) with icmp_data_len: {}, icmp_type: {}, icmp_code: {}, icmp_checksum: 0x{:X}",
                    (*ipv4hdr).src_addr.to_be(),
                    (*ethhdr).src_addr,
                    (*ipv4hdr).dst_addr.to_be(),
                    (*ethhdr).dst_addr,
                    icmp_data_len,
                    (*icmp_hdr).type_,
                    (*icmp_hdr).code,
                    (*icmp_hdr).checksum,
                );

                return Ok(XDP_DROP);
            }
            MSG_SIZE_RESPONSE => {
                // size responses can be ignored
                return Ok(XDP_DROP);
            }
            _ => {
                // Let's keep normal ICMP traffic
                return Ok(XDP_PASS);
            }
        }
    }

    // Let's keep normal ICMP traffic
    Ok(XDP_PASS)
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
