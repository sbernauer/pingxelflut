#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;

use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv6Hdr,
};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[xdp]
pub fn pingxelflut(ctx: XdpContext) -> u32 {
    match try_pingxelflut(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
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

fn try_pingxelflut(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;

    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv6 => {}
        _ => {
            return Ok(xdp_action::XDP_PASS);
        }
    }

    let ipv6hdr: *const Ipv6Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let dst = unsafe { (*ipv6hdr).dst_addr };

    let x = unsafe { dst.in6_u.u6_addr16.get_unchecked(5) }.to_be();
    let y = unsafe { dst.in6_u.u6_addr16.get_unchecked(6) }.to_be();
    let rgba = unsafe { dst.in6_u.u6_addr32.get_unchecked(3) }.to_be();

    info!(&ctx, "Got IPv6 with x {:x}, y {:x}, rgba {:x}", x, y, rgba);

    Ok(xdp_action::XDP_PASS)
}
