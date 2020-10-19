//! Dumps information about an XBE stored in its headers.

extern crate env_logger;
extern crate xbe;

#[allow(unused_imports)]
#[macro_use]
extern crate structopt;

use structopt::StructOpt;
use xbe::Xbe;

use std::error::Error;
use std::fs::read;
use std::path::PathBuf;

#[derive(Debug, StructOpt)]
#[structopt(name = "xbe-dump", about = "Dump info from XBE headers to stdout.")]
struct Opts {
    /// Path to the XBE file.
    #[structopt(parse(from_os_str))]
    xbe: PathBuf,
}

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let opts = Opts::from_args();

    let data = read(&opts.xbe)?;
    let xbe = Xbe::parse(&data)?;
    println!("{:#?}", xbe);
    Ok(())
}
