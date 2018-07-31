extern crate xbe;
extern crate env_logger;

use xbe::Xbe;

use std::{env, process};
use std::fs::read;
use std::error::Error;

fn main() -> Result<(), Box<Error>> {
    env_logger::init();

    let path = match env::args().nth(1) {
        Some(path) => path,
        None => {
            eprintln!("missing argument: path to XBE file");
            process::exit(1);
        }
    };

    let data = read(path)?;
    let xbe = Xbe::parse(&data)?;
    println!("{:#?}", xbe);
    Ok(())
}
