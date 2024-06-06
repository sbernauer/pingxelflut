#![no_std]
#![no_main]

use core::{mem, ptr::slice_from_raw_parts};

use aya_ebpf::{
    bindings::{
        xdp_action::{XDP_ABORTED, XDP_DROP, XDP_PASS, XDP_TX},
        BPF_F_MMAPABLE,
    },
    helpers::bpf_xdp_adjust_tail,
    macros::{map, xdp},
    maps::Array,
    programs::XdpContext,
};
// We always need this import, so that the log event array AYA_LOGS always exists
#[allow(unused_imports)]
use aya_log_ebpf::{info, warn};
use network_types::{
    eth::{EthHdr, EtherType},
    icmp::{IcmpHdr, ICMP_HDR_LEN},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
};

use pingxelflut_common::{
    CANVAS_HEIGHT, CANVAS_PIXELS, CANVAS_WIDTH, ICMP_TYPE_ECHO_REQUEST, ICMP_TYPE_ECHO_RESPONSE,
    MSG_GET_SIZE_REQUEST, MSG_SET_PIXEL, MSG_SIZE_RESPONSE,
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
fn array_at<T>(ctx: &XdpContext, offset: usize, len: usize) -> Result<*const [T], ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let element_size = mem::size_of::<T>();

    if start + offset + len * element_size > end {
        return Err(());
    }

    Ok(slice_from_raw_parts((start + offset) as *const T, len))
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
        let mut ipv4_total_len = (*ipv4hdr).tot_len.to_be();
        let mut icmp_data_len =
            ctx.data_end() - ctx.data() - EthHdr::LEN - Ipv4Hdr::LEN - IcmpHdr::LEN;
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
                    // info!(ctx, "Read rgb with x: {}, y: {}, rgb: 0x{:x}", x, y, rgb);

                    set_pixel(&ctx, x, y, rgb);
                    return Ok(XDP_DROP);

                // With alpha
                // We don't check for exact 4 here, so that clients can send longer than needed packages because
                // - why not?
                } else if remaining > 4 {
                    let rgba = u32::from_be_bytes(*ptr_at(
                        ctx,
                        EthHdr::LEN + Ipv4Hdr::LEN + IcmpHdr::LEN + 5,
                    )?);

                    // info!(ctx, "Read rgba with x: {}, y: {}, rgba: 0x{:x}", x, y, rgba);
                    set_pixel(&ctx, x, y, rgba);
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

                // (*icmp_hdr).checksum = 0;

                let icmp_packet: &[u8] =
                    &*array_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN, ICMP_HDR_LEN + 1)?;
                let _ = internet_checksum(ctx, icmp_packet);

                let ip_header: &[u8] = &*array_at(ctx, EthHdr::LEN, Ipv4Hdr::LEN)?;
                let _ = internet_checksum(ctx, ip_header);

                // Swap source and target MAC to send packet back
                let old_src = (*ethhdr).src_addr;
                (*ethhdr).src_addr = (*ethhdr).dst_addr;
                (*ethhdr).dst_addr = old_src;

                // Swap source and target IP to send packet back
                let old_src = (*ipv4hdr).src_addr;
                (*ipv4hdr).src_addr = (*ipv4hdr).dst_addr;
                (*ipv4hdr).dst_addr = old_src;

                // Set ICMP return type
                (*icmp_hdr).type_ = ICMP_TYPE_ECHO_RESPONSE;
                // code is already set to 0 from the request

                // Set response type
                unsafe { *msg_kind = MSG_SIZE_RESPONSE };

                let data_increment = 5 as i32 - icmp_data_len as i32;
                bpf_xdp_adjust_tail(ctx.ctx, data_increment as i32);
                icmp_data_len = (icmp_data_len as i32 + data_increment as i32) as usize;
                ipv4_total_len = (ipv4_total_len as i32 + data_increment as i32) as u16;

                let width: *mut u16 =
                    mut_ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN + IcmpHdr::LEN + 1)?;
                let height: *mut u16 =
                    mut_ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN + IcmpHdr::LEN + 3)?;

                unsafe {
                    *width = CANVAS_WIDTH.to_be();
                    *height = CANVAS_HEIGHT.to_be();
                }

                // We need to re-create the structs to prove the verifier it is still valid memory access
                let icmp_hdr: *mut IcmpHdr = mut_ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                let ipv4hdr: *mut Ipv4Hdr = mut_ptr_at(&ctx, EthHdr::LEN)?;

                // We need to set the checksum to zero so that we calculate the real checksum.
                (*icmp_hdr).checksum = 0;
                let icmp_packet: *const [u8] = array_at(
                    ctx,
                    EthHdr::LEN + Ipv4Hdr::LEN,
                    ICMP_HDR_LEN + icmp_data_len,
                )?;
                let checksum = internet_checksum(ctx, unsafe { &*icmp_packet });
                (*icmp_hdr).checksum = checksum.to_be();

                // info!(
                //     ctx,
                //     "Current length: {}, must be {}",
                //     (*ipv4hdr).tot_len.to_be(),
                //     ipv4_total_len
                // );
                (*ipv4hdr).tot_len = ipv4_total_len.to_le();
                // As we send the packet back we need to reset the ttl.
                (*ipv4hdr).ttl = 255;

                // We need to set the checksum to zero so that we calculate the real checksum.
                (*ipv4hdr).check = 0;
                let ip_header: *const [u8] = array_at(ctx, EthHdr::LEN, Ipv4Hdr::LEN)?;
                let checksum = internet_checksum(ctx, unsafe { &*ip_header });
                (*ipv4hdr).check = checksum.to_be();

                info!(
                    ctx,
                    "[SIZE] Responding to size request with icmp_data_len: {}, icmp_type: {}, icmp_code: {}, icmp_checksum: 0x{:X}",
                    // (*ipv4hdr).src_addr.to_be(),
                    // (*ethhdr).src_addr,
                    // (*ipv4hdr).dst_addr.to_be(),
                    // (*ethhdr).dst_addr,
                    icmp_data_len,
                    (*icmp_hdr).type_,
                    (*icmp_hdr).code,
                    (*icmp_hdr).checksum,
                );

                return Ok(XDP_TX);
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

/// The checksum must be set to 0 before calling this function!
#[inline(always)]
fn internet_checksum(ctx: &XdpContext, icmp_packet: &[u8]) -> u16 {
    let mut checksum = 0_u32;

    for word in icmp_packet.chunks(2) {
        let mut part = u16::from(word[0]) << 8;
        if word.len() > 1 {
            part += u16::from(word[1]);
        }
        checksum = checksum.wrapping_add(u32::from(part));
    }
    info!(ctx, "checksum step 1: 0x{:X}", checksum);
    while (checksum >> 16) > 0 {
        checksum = (checksum & 0xffff) + (checksum >> 16);
    }
    info!(ctx, "checksum step 2: 0x{:X}", checksum);

    let checksum = !checksum as u16;

    info!(
        ctx,
        "Calculated checksum 0x{:X} for {} bytes (data is 0x{:X})",
        checksum,
        icmp_packet.len(),
        icmp_packet,
    );

    checksum
}
