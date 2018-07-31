extern crate xbe;
#[macro_use] extern crate honggfuzz;

fn main() {
    loop {
        fuzz!(|data: &[u8]| {
            xbe::Xbe::parse(data).ok();
        });
    }
}
