use clap::Parser;

#[derive(Debug, Parser)]
pub struct Args {
    #[clap(short = 'i', long)]
    pub interface: String,

    #[clap(short = 's', long)]
    pub pixelflut_sink: String,

    #[clap(short = 't', long, default_value = "10")]
    pub drawing_threads: u16,

    #[clap(short = 'f', long, default_value = "30")]
    pub fps: u32,
}
