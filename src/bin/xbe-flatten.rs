//! Flatten an XBE into its would-be virtual address space.
//!
//! This is useful for looking up code and data addresses with the static XBE
//! data.

extern crate xbe;
extern crate env_logger;
#[macro_use] extern crate structopt;

use xbe::Xbe;
use structopt::StructOpt;

use std::fs::{File, read};
use std::io::{self, BufWriter, Write, Seek, SeekFrom};
use std::path::PathBuf;
use std::error::Error;

const DEFAULT_OUTPUT_EXTENSION: &'static str = "flat";

/// Filler byte used for data that is not mapped from the XBE.
const FILLER: u8 = 0;

#[derive(Debug, StructOpt)]
#[structopt(name = "xbe-flatten", about = "Converts an XBE file to a file containing all sections at their expected virtual addresses.")]
struct Opts {
    /// Path to the XBE file.
    #[structopt(parse(from_os_str))]
    xbe: PathBuf,
    /// The output file. If not specified, output goes to a file next to the
    /// XBE, with the extension changed to `.flat`.
    #[structopt(parse(from_os_str))]
    output: Option<PathBuf>,
}

fn fill_up_to<W: Write + Seek>(writer: &mut W, pos: u64) -> Result<(), io::Error> {
    let current = writer.seek(SeekFrom::Current(0))?;
    for _ in current..pos {
        writer.write(&[FILLER])?;
    }
    Ok(())
}

fn main() -> Result<(), Box<Error>> {
    env_logger::init();
    let opt = Opts::from_args();

    eprintln!("Reading from {}", opt.xbe.display());
    let data = read(&opt.xbe)?;
    let out = opt.output.unwrap_or(opt.xbe.with_extension(DEFAULT_OUTPUT_EXTENSION));
    eprintln!("  Writing to {}", out.display());
    let mut out = BufWriter::new(File::create(&out)?);
    let xbe = Xbe::parse(&data)?;

    // Fill with zeros up to the base address
    fill_up_to(&mut out, xbe.base_address().into())?;

    // Headers
    out.write_all(&xbe.raw_data()[0..xbe.header_size() as usize])?;

    // Sections

    // First, sort them by virtual start address
    let mut sections = xbe.sections().collect::<Vec<_>>();
    sections.sort_by_key(|section| *section.virt_range().start());

    // Now, for each section, fill the file with zeros until the section's start
    // address.
    for section in sections {
        fill_up_to(&mut out, u64::from(*section.virt_range().start()))?;
        out.write_all(section.data())?;
    }

    Ok(())
}
