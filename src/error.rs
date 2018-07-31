use std::{error, fmt, io};

/// The error type used by the `xbe` library.
#[derive(Debug)]
pub enum Error {
    Malformed(String),
    Io(io::Error),
}

impl Error {
    /// Creates an `Error` denoting that an address computation would have lead
    /// to an overflow.
    pub(crate) fn addr_overflow(base: u32, offset: u32) -> Self {
        Error::Malformed(format!(
            "invalid address or length: address computation overflow ({:#08X}+{:#08X})",
            base, offset
        ))
    }
}

impl error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Malformed(s) => write!(f, "malformed data: {}", s),
            Error::Io(io) => write!(f, "i/o error: {}", io),
        }
    }
}

impl From<io::Error> for Error {
    fn from(io: io::Error) -> Self {
        Error::Io(io)
    }
}
