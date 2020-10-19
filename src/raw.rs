//! Raw structures that can be deserialized from binary data.
//!
//! Generally, the structure in here have a very loose structure in that they
//! don't try to verify their values if not necessary. They also store most
//! things as raw values instead of more convenient types. That's left to do for
//! the user-facing wrappers.
//!
//! This module also serves to document the basic memory layout of the XBE
//! structures: All struct fields are parsed in-order and are deserialized
//! using `bincode` (no padding is used anywhere and the layout is mostly
//! "obvious").
//!
//! Everything is Little Endian.

use crate::Error;
use serde::de;

use std::{fmt, u32};
use std::marker::PhantomData;

// All addresses refer to the address *after* loading the XBE into memory

#[derive(Debug, Deserialize)]
pub struct Header {
    /// Magic number, must be equal to the constant `MAGIC_NUMBER`.
    pub magic: u32,
    /// MS signature.
    pub signature: Signature,
    /// Address at which the whole XBE image should be loaded.
    pub base_addr: u32,
    pub header_size: u32,
    pub image_size: u32,
    pub image_header_size: u32,
    /// Creation time of the file as a Unix timestamp.
    pub time_date: u32,
    /// Address of a `Certificate` struct.
    pub cert_addr: u32,
    pub num_sections: u32,
    /// Address of an array of `SectionHeader` structs.
    pub section_headers_addr: u32,
    /// Raw init flags.
    ///
    /// Can be converted to `InitFlags`, which contains the known flags.
    pub init_flags: u32,
    /// Start address of execution, XOR encoded.
    pub entry_point: u32,
    /// Address of a `Tls` struct.
    pub tls_addr: u32,
    pub pe_stack_commit: u32,
    pub pe_heap_reserve: u32,
    pub pe_heap_commit: u32,
    pub pe_base_addr: u32,
    pub pe_size: u32,
    pub pe_checksum: u32,
    pub pe_time_date: u32,
    /// Address of a C string for the debug pathname (full path to exec file).
    pub debug_pathname_addr: u32,
    /// Address of a C string for the debug filename (without the path).
    pub debug_filename_addr: u32,
    /// Same as `debug_filename_addr`, but as a "long string".
    pub debug_unicode_filename_addr: u32,
    /// Address of the kernel thunk, XOR encoded.
    ///
    /// The kernel thunk is an array of 32-bit IDs that identify a kernel symbol
    /// to import. The last ID is 0 and signals the end of the thunk array.
    ///
    /// When the XBE file is loaded, each ID is replaced by the kernel symbol
    /// address by masking it with `0x1ff` and looking up the result in
    /// [this table].
    ///
    /// [this table]: http://xboxdevwiki.net/Kernel#Kernel_exports
    pub kernel_thunk_addr: u32,
    /// Address of the Non-Kernel Import Directory.
    ///
    /// Can be set to zero and (hopefully) ignored.
    pub non_kernel_import_dir_addr: u32,
    /// Length of the array at `library_versions_addr`.
    pub num_library_versions: u32,
    /// Address of an array of `LibraryVersion` structures.
    pub library_versions_addr: u32,
    /// Address of a `LibraryVersion` struct.
    pub kernel_library_version_addr: u32,
    /// Address of a `LibraryVersion` struct.
    pub xapi_library_version_addr: u32,
    /// Address of a logo bitmap.
    pub logo_bitmap_addr: u32,
    /// Logo bitmap size in Bytes.
    pub logo_bitmap_size: u32,
}

impl Header {
    pub fn parse(data: &mut &[u8]) -> Result<Self, Error> {
        ::bincode::deserialize_from(data).map_err(|e| Error::Malformed(format!("{:?}", e)))
    }

    /// Translates an address inside a header to an address relative to the
    /// start of the XBE image (the "RVA" - Relative Virtual Address).
    ///
    /// Normally, addresses inside the XBE header refer to the address after the
    /// XBE has been mapped to the base address.
    pub fn rel_addr(&self, addr: u32) -> u32 {
        // `addr` must be larger than `base_addr`. If it's not, this is an
        // invalid operation and we just return the largest possible value which
        // will trigger an out of bounds access later.

        addr.checked_sub(self.base_addr)
            .unwrap_or(u32::MAX)
    }
}

/// A serde visitor that deserializes a fixed number of elements as a sequence
/// and passes them to a closure to be put into the final result type.
struct SliceAdapter<F, S: 'static, R>
where F: FnOnce(&[S]) -> R {
    /// Maps the decoded byte slice to the final result value of type `T`.
    ///
    /// The passed slice always has length `num_bytes`.
    map: F,
    /// A string describing what kind of item was expected.
    expected: &'static str,
    /// Number of elements to decode from the stream.
    num_elements: usize,
    _phantom: PhantomData<&'static S>,
}

impl<F, S: 'static, R> SliceAdapter<F, S, R>
where F: FnOnce(&[S]) -> R {
    fn new(map: F, expected: &'static str, num_bytes: usize) -> Self {
        Self {
            map, expected,
            num_elements: num_bytes,
            _phantom: PhantomData,
        }
    }
}

impl<'de, F, S: 'static, R> de::Visitor<'de> for SliceAdapter<F, S, R>
where
    F: FnOnce(&[S]) -> R,
    S: de::Deserialize<'de>
{
    type Value = R;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{}", self.expected)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error> where
        A: de::SeqAccess<'de>, {

        // *chants* GIVE US CONST GENERICS NOW!
        // Seriously the number of times I could've vastly simplified, sped up
        // and deduplicated code if const generics were a thing is enormous.
        let mut buf = Vec::with_capacity(self.num_elements);
        while let Some(byte) = seq.next_element::<S>()? {
            buf.push(byte);
        }

        Ok((self.map)(&buf))
    }
}

/// This type exists solely because `[u8; 256]` doesn't implement `Debug`.
///
/// Remove it once we have const generics.
#[derive(Copy, Clone)]
pub struct Signature(pub [u8; 256]);

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let slice: &[u8] = &self.0;
        write!(f, "0x")?;
        for b in slice {
            write!(f, "{:02X}", b)?;
        }
        Ok(())
    }
}

impl<'de> de::Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where
        D: de::Deserializer<'de> {

        // we use tuple instead of seq or bytes here since we know the length
        deserializer.deserialize_tuple(256, SliceAdapter::new(
            |slice| {
                let mut buf = [0; 256];
                buf.copy_from_slice(slice);
                Signature(buf)
            },
            "signature blob (256 Bytes)",
            256,
        ))
    }
}

#[derive(Debug, Deserialize)]
pub struct Certificate {
    /// Certificate size in Bytes.
    pub size: u32,
    pub time_date: u32,
    pub title_id: u32,
    /// Title name of the application, wide string of up to 40 code points (chars?).
    pub title_name: TitleName,  // 0x50 bytes
    /// Array of alternative `title_id`s (or zeros).
    pub alt_title_ids: [u32; 16],
    /// Allowed media types.
    ///
    /// Known flags in this bitmask are listed as `MediaTypes`.
    pub allowed_media: u32,
    /// See `GameRegion`.
    pub game_region: u32,
    pub game_ratings: u32,
    pub disk_number: u32,
    pub version: u32,
    pub lan_key: [u8; 16],
    pub signature_key: [u8; 16],
    /// Alternative signature keys.
    pub alt_signature_keys: [[u8; 16]; 16],
}

impl Certificate {
    pub fn parse(data: &mut &[u8]) -> Result<Self, Error> {
        ::bincode::deserialize_from(data)
            .map_err(|e| Error::Malformed(format!("{:?}", e)))
    }
}

/// This type exists solely because `[u16; 40]` doesn't implement `Debug`.
///
/// Remove it once we have const generics.
pub struct TitleName(pub [u16; 40]);

impl fmt::Debug for TitleName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let slice: &[u16] = &self.0;
        slice.fmt(f)
    }
}

impl<'de> de::Deserialize<'de> for TitleName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where
        D: de::Deserializer<'de> {

        // we use tuple instead of seq or bytes here since we know the length
        deserializer.deserialize_tuple(40, SliceAdapter::new(
            |slice| {
                let mut buf = [0u16; 40];
                buf.copy_from_slice(slice);
                TitleName(buf)
            },
            "title name (80 Bytes)",
            40,
        ))
    }
}

#[derive(Debug, Deserialize)]
pub struct SectionHeader {
    /// See `SectionFlags`.
    pub section_flags: u32,
    /// Virtual address where this section should be mapped to.
    pub virt_addr: u32,
    pub virt_size: u32, // TODO: document handling of size differences (virt_size vs raw_size)
    /// Address of the section content inside the XBE image.
    pub raw_addr: u32,
    pub raw_size: u32,
    /// Address of the section's name string. The string is zero terminated and
    /// probably ASCII.
    pub section_name_addr: u32,
    /// TODO: Some sort of reference count? Can usually be ignored and set to 0.
    pub section_name_refcount: u32,
    pub head_shared_page_refcount_addr: u32,
    pub tail_shared_page_refcount_addr: u32,
    /// Signature digest.
    pub section_digest: [u8; 20],
}

impl SectionHeader {
    pub fn parse(data: &mut &[u8]) -> Result<Self, Error> {
        ::bincode::deserialize_from(data)
            .map_err(|e| Error::Malformed(format!("{:?}", e)))
    }
}

#[derive(Debug, Deserialize)]
pub struct LibraryVersion {
    /// 8-byte name of the library.
    pub library_name: [u8; 8],
    pub major_version: u16,
    pub minor_version: u16,
    pub build_version: u16,
    /// See `LibraryFlags`.
    ///
    /// [Caustik's docs] claim that this is a `u32` with an offset of `0x0124`.
    /// This is false. It's a `u16` with no special offset or padding, it
    /// directly follows the preceding fields.
    ///
    /// [Caustik's docs]: http://www.caustik.com/cxbx/download/xbe.htm
    pub library_flags: u16,
}

impl LibraryVersion {
    pub fn parse(data: &mut &[u8]) -> Result<Self, Error> {
        ::bincode::deserialize_from(data)
            .map_err(|e| Error::Malformed(format!("{:?}", e)))
    }
}

#[derive(Debug, Deserialize)]
pub struct Tls {
    pub data_start_addr: u32,
    pub data_end_addr: u32,
    pub tls_index_addr: u32,
    pub tls_callback_addr: u32,
    pub zero_fill_size: u32,
    pub characteristics: u32,
}

impl Tls {
    pub fn parse(data: &mut &[u8]) -> Result<Self, Error> {
        ::bincode::deserialize_from(data)
            .map_err(|e| Error::Malformed(format!("{:?}", e)))
    }
}
