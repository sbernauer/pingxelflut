use std::{
    os::fd::{AsFd, AsRawFd},
    slice,
    time::Duration,
};

use anyhow::{Context, Ok};
use aya::{
    include_bytes_aligned,
    programs::{Xdp, XdpFlags},
    Bpf,
};
use aya_log::BpfLogger;
use clap::Parser;
use log::{debug, info, warn};
use memmap2::MmapOptions;
use pingxelflut_common::{CANVAS_HEIGHT, CANVAS_PIXELS, CANVAS_WIDTH};
use tokio::{signal, time};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "lo")]
    interface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/pingxelflut"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/pingxelflut"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut Xdp = bpf.program_mut("pingxelflut").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.interface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let framebuffer_map = bpf
        .map("FRAMEBUFFER")
        .expect("No map with name FRAMEBUFFER found");
    let framebuffer_fd = match &framebuffer_map {
        aya::maps::Map::Array(map) => map.fd(),
        _ => panic!("framebuffer must be array"),
    };

    // Memory alignment: I would have expected the mmap region to contain `u32[CANVAS_PIXELS]`.
    // For *some* reasons the kernel padds the value size to u64, so let's use that.
    // The array type is `u64`, we can safely read `u32` out of it anyway.
    let mmap = MmapOptions::new()
        .len(CANVAS_PIXELS as usize * 8)
        .map_raw_read_only(framebuffer_fd.as_fd().as_raw_fd())?;
    let fb: &[u64] =
        unsafe { slice::from_raw_parts(mmap.as_mut_ptr() as _, CANVAS_PIXELS as usize) };

    tokio::spawn(main_loop(fb));

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}

async fn main_loop(fb: &[u64]) {
    loop {
        for x in 0..CANVAS_WIDTH {
            for y in 0..CANVAS_HEIGHT {
                let rgb =
                    unsafe { *fb.get_unchecked(x as usize + y as usize * CANVAS_WIDTH as usize) }
                        as u32;
                if rgb != 0 {
                    println!("PX {x} {y} {rgb:x}");
                }
            }
        }
        println!();

        time::sleep(Duration::from_secs(1)).await;
    }
}
