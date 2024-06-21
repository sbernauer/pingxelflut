use std::{
    os::fd::{AsFd, AsRawFd},
    slice,
    time::Duration,
};

use anyhow::{Context, Result};
use aya::{
    include_bytes_aligned,
    programs::{Xdp, XdpFlags},
    Bpf,
};
use aya_log::BpfLogger;
use clap::Parser;
use log::{debug, error, info, trace, warn};
use memmap2::MmapOptions;
use pingxelflut_common::{CANVAS_PIXELS, CANVAS_WIDTH};
use tokio::{io::AsyncWriteExt, net::TcpStream, signal, time};

use args::Args;

mod args;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args = Args::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
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
    program.attach(&args.interface, XdpFlags::default())
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
    let mut mmap = unsafe {
        MmapOptions::new()
            .len(CANVAS_PIXELS as usize * 8)
            .map_mut(framebuffer_fd.as_fd().as_raw_fd())?
    };
    let fb: &mut [u64] =
        unsafe { slice::from_raw_parts_mut(mmap.as_mut_ptr() as _, CANVAS_PIXELS as usize) };

    if args.disable_pixelflut_sink {
        info!("Not starting drawing threads");
    } else {
        info!("Starting {} drawing threads", args.drawing_threads);
        let thread_chunk_size = (fb.len() / args.drawing_threads as usize) + 1;
        let mut index = 0;
        for fb_slice in fb.chunks_mut(thread_chunk_size) {
            let start_x = (index % CANVAS_WIDTH as usize) as u16;
            let start_y = (index / CANVAS_WIDTH as usize) as u16;
            index += fb_slice.len();

            let sink = TcpStream::connect(&args.pixelflut_sink)
                .await
                .with_context(|| {
                    format!(
                        "Failed to connect to Pixelflut sink at {}",
                        &args.pixelflut_sink
                    )
                })?;

            tokio::spawn(drawing_thread(fb_slice, sink, args.fps, start_x, start_y));
        }
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}

async fn drawing_thread(
    fb_slice: &mut [u64],
    mut sink: TcpStream,
    fps: u32,
    start_x: u16,
    start_y: u16,
) -> Result<()> {
    let mut interval = time::interval(Duration::from_micros(1_000_000 / fps as u64));

    loop {
        let start = std::time::Instant::now();
        let mut x = start_x;
        let mut y = start_y;

        for rgba in fb_slice.iter_mut() {
            // Ignore alpha channel
            let rgb = *rgba >> 8;

            // Only send pixels that
            // 1.) The server is responsible for
            // 2.) Have changed sind the last flush
            if rgb != 0 {
                sink.write_all(format!("PX {x} {y} {rgb:06x}\n").as_bytes())
                    .await
                    .context("Failed to write to Pixelflut sink")?;

                // Reset color back, so that we don't send the same color twice
                *rgba = 0;
            }

            x += 1;
            if x >= CANVAS_WIDTH {
                x = 0;
                y += 1;
                if y >= CANVAS_WIDTH { // FIXME: Change to CANVAS_HEIGHT and fix upcoming errors
                    error!("x and y run over the fb bounds. This should not happen, as no thread should get work to do that");
                    break;
                }
            }
        }

        let elapsed = start.elapsed();
        trace!(
            "Loop took {:?} ({}% of duty cycle)",
            elapsed,
            (elapsed.as_micros() as f32 / interval.period().as_micros() as f32 * 100.0).ceil()
        );

        sink.flush()
            .await
            .context("Failed to flush to Pixelflut sink")?;

        interval.tick().await;
    }
}
