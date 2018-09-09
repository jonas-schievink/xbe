//! Dumps information about an XBE stored in its headers.

extern crate xbe;
extern crate env_logger;
#[macro_use] extern crate structopt;

use xbe::Xbe;
use structopt::StructOpt;

use std::fs::read;
use std::path::PathBuf;
use std::error::Error;

#[derive(Debug, StructOpt)]
#[structopt(name = "xbe-dump", about = "Dump info from XBE headers to stdout.")]
struct Opts {
    /// Path to the XBE file.
    #[structopt(parse(from_os_str))]
    xbe: PathBuf,
}

fn main() -> Result<(), Box<Error>> {
    env_logger::init();

    let opts = Opts::from_args();

    let data = read(&opts.xbe)?;
    let xbe = Xbe::parse(&data)?;
    println!("{:#?}", xbe);
    Ok(())
}
