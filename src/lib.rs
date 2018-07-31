//! Parser for the `XBE` file format used by Xbox executables.
//!
//! Most of the information in here is derived from
//! [http://www.caustik.com/cxbx/download/xbe.htm][website].
//!
//! The most important type is [`Xbe`], which allows the user to parse an XBE
//! image from a byte slice.
//!
//! [website]: http://www.caustik.com/cxbx/download/xbe.htm
//! [`Xbe`]: struct.Xbe.html

#![doc(html_root_url = "https://docs.rs/xbe/0.1.0")]

// Deny unchecked slice indexing when using clippy. This can almost always
// result in a panic with a malformed XBE.
#![cfg_attr(feature = "cargo-clippy", deny(indexing_slicing))]
#![cfg_attr(feature = "cargo-clippy", allow(unreadable_literal, large_digit_groups))]

#[macro_use] extern crate bitflags;
#[macro_use] extern crate log;
#[macro_use] extern crate serde_derive;
extern crate serde;
extern crate bincode;
extern crate scroll;
extern crate byteorder;
extern crate core;

pub mod cert;
mod error;
mod kernel_symbols;
mod logo;
mod raw;
mod utils;

pub use error::Error;
pub use logo::LogoBitmap;
use cert::Certificate;
use utils::{SliceExt, NoDebug};

use byteorder::{ReadBytesExt, LE};
use std::time::{UNIX_EPOCH, SystemTime, Duration};
use std::ops::RangeInclusive;
use std::{fmt, u32};

/// "XBEH"
const MAGIC_NUMBER: u32 = 0x48454258;

const ENTRY_XOR_DEBUG: u32 = 0x94859D4B;
const ENTRY_XOR_RETAIL: u32 = 0xA8FC57AB;
const THUNK_XOR_DEBUG: u32 = 0xEFB1F152;
const THUNK_XOR_RETAIL: u32 = 0x5B6D40B6;

/// An analyzed Xbox executable (XBE).
///
/// Using the `parse` method, you can parse an `Xbe` from raw bytes.
///
/// The `Xbe` type provides access to the parsed `Header` as well as a few
/// utility methods that make useful operations easier.
#[derive(Debug)]
pub struct Xbe<'a> {
    header: Header,
    image_kind: ImageKind,
    /// The raw XBE image data.
    data: NoDebug<&'a [u8]>,
    thunk_table: KernelThunkTable,
}

impl<'a> Xbe<'a> {
    /// Tries to parse an XBE file from raw data.
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() >= u32::MAX as usize {
            return Err(Error::Malformed(format!("image too large ({} Bytes)", data.len())));
        }

        let header = Header::from_raw(&raw::Header::parse(&mut &*data)?, data)?;

        let mut image_kind = None;
        for &kind in &[ImageKind::Retail, ImageKind::Debug] {
            let (entry_addr, thunk_addr) = (header.entry_point(kind), header.kernel_thunk_addr(kind));
            let (entry_info, thunk_info) = (header.find_address_info(entry_addr), header.find_address_info(thunk_addr));
            info!("{:?} entry point: {}", kind, entry_info);
            info!("{:?} thunk addr: {}", kind, thunk_info);

            if entry_info.section().is_some() && thunk_info.section().is_some() {
                info!("both addrs good, image kind probably {:?}", kind);
                image_kind = Some(kind);
                break;
            }
        }

        let image_kind = image_kind.unwrap_or_else(|| {
            let fallback = ImageKind::Retail;
            warn!("couldn't determine image kind, falling back to {:?}", fallback);
            fallback
        });

        Ok(Self {
            thunk_table: {
                let virt_addr = header.kernel_thunk_addr(image_kind);
                let raw_addr = header.translate_virt_addr(virt_addr)
                    .ok_or_else(|| Error::Malformed(format!(
                        "kernel thunk virt. address {:#08X} not mapped", virt_addr
                    )))?;

                KernelThunkTable::from_raw(data, virt_addr, raw_addr)?
            },
            header,
            image_kind,
            data: NoDebug::from(data),
        })
    }

    /// Returns the decoded title name from the image's included certificate.
    ///
    /// If the name contains invalid UTF-16, the returned string will have
    /// replacement characters in their place.
    pub fn title_name(&self) -> &str {
        self.header.cert.title_name()
    }

    /// Returns the entry point of the XBE (virtual address).
    ///
    /// This uses a heuristic to determine whether the entry point is encoded as
    /// for retail or debug XBEs.
    pub fn entry_point(&self) -> u32 {
        self.header.entry_point(self.image_kind)
    }

    /// Gets the decoded kernel thunk table.
    ///
    /// The thunk table stores IDs of kernel functions the XBE wants to import.
    /// These imports are resolved by the loader just before the XBE is
    /// launched.
    ///
    /// The address of the kernel thunk table is encoded in a similar fashion as
    /// the entry point, and so also depends on the heuristic to determine the
    /// image kind.
    pub fn kernel_thunk_table(&self) -> &KernelThunkTable {
        &self.thunk_table
    }

    /// Get a reference to the parsed image header.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Get a reference to the section headers in the image.
    pub fn section_headers(&self) -> &[SectionHeader] {
        &self.header.section_headers
    }

    /// Returns an iterator over the sections in this XBE.
    pub fn sections(&self) -> Sections {
        Sections::new(&self.header.section_headers, &*self.data)
    }
}

/// Describes whether an XBE is for debug or retail models of the Xbox.
///
/// This is sort of guessed when the image is loaded and is only encoded in the
/// way the entry point and kernel thunk are XORed with different masks
/// depending on whether it's a retail or debug image.
#[derive(Debug, Copy, Clone)]
pub enum ImageKind {
    /// An XBE for retail Xboxes.
    Retail,
    /// An XBE for debug Xboxes / devkits.
    Debug,
}

/// Main XBE header.
///
/// Contains the locations of all other headers.
#[derive(Debug)]
pub struct Header {
    /// MS signature.
    signature: raw::Signature,
    /// Address at which the XBE image should be loaded.
    base_addr: u32,
    header_size: u32,
    image_size: u32,
    image_header_size: u32,
    /// Creation time of the file.
    time_date: SystemTime,
    /// The `Certificate` of this XBE.
    cert: Certificate,
    /// Section headers found in the main header.
    section_headers: Vec<SectionHeader>,
    /// Raw init flags.
    ///
    /// Can be converted to `InitFlags`, which contains the known flags.
    init_flags: InitFlags,
    /// Start address of execution, XOR encoded.
    entry_point: u32,
    /// The decoded `Tls` struct.
    tls: raw::Tls,
    pe_stack_commit: u32,
    pe_heap_reserve: u32,
    pe_heap_commit: u32,
    pe_base_addr: u32,
    pe_size: u32,
    pe_checksum: u32,
    pe_time_date: SystemTime,
    /// Debug pathname (full path to exec file).
    debug_pathname: String,
    /// Debug filename (without the path).
    debug_filename: String,
    /// Same as `debug_filename`, but as a "long string" (UTF-16).
    debug_unicode_filename: String,
    /// Address of the kernel thunk, XOR encoded.
    ///
    /// The kernel thunk is an array of 32-bit IDs that identify a kernel symbol
    /// to import. The last ID is 0 and signals the end of the thunk array.
    ///
    /// When the XBE file is loaded, each ID is replaced by the kernel symbol
    /// address by masking it with `0x1ff` and looking up the export ID in
    /// [this table].
    ///
    /// [this table]: http://xboxdevwiki.net/Kernel#Kernel_exports
    kernel_thunk_addr: u32,
    /// Address of the Non-Kernel Import Directory.
    ///
    /// Can be set to zero and (hopefully) ignored.
    non_kernel_import_dir_addr: u32,
    /// List of `LibraryVersion` structures.
    library_versions: Vec<LibraryVersion>,
    /// `LibraryVersion` struct for the kernel (?).
    kernel_library_version: Option<LibraryVersion>,
    /// `LibraryVersion` struct for XAPI.
    xapi_library_version: Option<LibraryVersion>,
    /// The decoded logo bitmap.
    logo_bitmap: LogoBitmap,
}

impl Header {
    fn from_raw(raw: &raw::Header, data: &[u8]) -> Result<Self, Error> {
        // Decodes an ASCII C-String (null terminated) starting at the given
        // image offset (virtual address, VA).
        let decode_cstring = |addr: u32| -> Result<String, Error> {
            if addr == 0 {
                Ok(String::new())
            } else {
                let addr = raw.rel_addr(addr);
                let string = data.try_get(addr..)?.iter()
                    .take_while(|b| **b != 0)
                    .map(|b| *b as char)
                    .collect::<String>();

                Ok(string)
            }
        };

        // Decodes a "long string", a UTF-16 encoded string terminated with a
        // null word.
        let decode_utf16 = |addr: u32| -> Result<String, Error> {
            if addr == 0 {
                Ok(String::new())
            } else {
                let addr = raw.rel_addr(addr);
                let mut words = Vec::with_capacity(16);
                let mut reader = data.try_get(addr..)?;
                loop {
                    let word = reader.read_u16::<LE>()?;
                    if word == 0 {
                        break;
                    } else {
                        words.push(word);
                    }
                }

                Ok(String::from_utf16_lossy(&words))
            }
        };

        if raw.magic != MAGIC_NUMBER {
            return Err(Error::Malformed(format!(
                "invalid magic number (got {:#X}, expected {:#X}", raw.magic, MAGIC_NUMBER
            )));
        }

        Ok(Self {
            signature: raw.signature,
            base_addr: raw.base_addr,
            header_size: raw.header_size,
            image_size: raw.image_size,
            image_header_size: raw.image_header_size,
            time_date: UNIX_EPOCH + Duration::from_secs(raw.time_date.into()),
            cert: {
                let cert_addr = raw.rel_addr(raw.cert_addr);
                Certificate::from_raw(&raw::Certificate::parse(&mut data.try_get(cert_addr..)?)?)?
            },
            section_headers: {
                let mut section_headers = Vec::with_capacity(raw.num_sections as usize);
                let section_header_addr = raw.rel_addr(raw.section_headers_addr);
                let mut section_header_slice = data.try_get(section_header_addr..)?;
                for _ in 0..raw.num_sections {
                    let raw_sh = raw::SectionHeader::parse(&mut section_header_slice)?;
                    section_headers.push(SectionHeader::from_raw(&raw, &raw_sh, data)?);
                }
                section_headers
            },
            init_flags: {
                let flags = InitFlags::from_bits_truncate(raw.init_flags);
                if flags.bits() != raw.init_flags {
                    warn!("unknown init flags: known flags: {:#X}, raw flags: {:#X}", flags.bits(), raw.init_flags);
                }
                flags
            },
            entry_point: raw.entry_point,
            tls: {
                let tls_addr = raw.rel_addr(raw.tls_addr);
                raw::Tls::parse(&mut data.try_get(tls_addr..)?)?
            },
            pe_stack_commit: raw.pe_stack_commit,
            pe_heap_reserve: raw.pe_heap_reserve,
            pe_heap_commit: raw.pe_heap_commit,
            pe_base_addr: raw.pe_base_addr,
            pe_size: raw.pe_size,
            pe_checksum: raw.pe_checksum,
            pe_time_date: UNIX_EPOCH + Duration::from_secs(raw.pe_time_date.into()),
            debug_pathname: decode_cstring(raw.debug_pathname_addr)?,
            debug_filename: decode_cstring(raw.debug_filename_addr)?,
            debug_unicode_filename: decode_utf16(raw.debug_unicode_filename_addr)?,
            kernel_thunk_addr: raw.kernel_thunk_addr,   // can't really decode this due to encoding
            non_kernel_import_dir_addr: raw.non_kernel_import_dir_addr,
            library_versions: {
                let addr = raw.rel_addr(raw.library_versions_addr);
                let mut slice = data.try_get(addr..)?;

                debug!("{} library version structs at {}+", raw.num_library_versions, addr);

                (0..raw.num_library_versions)
                    .map(|_| LibraryVersion::from_raw(&raw::LibraryVersion::parse(&mut slice)?))
                    .collect::<Result<_, _>>()?
            },
            kernel_library_version: {
                if raw.kernel_library_version_addr == 0 {
                    None
                } else {
                    let addr = raw.rel_addr(raw.kernel_library_version_addr);
                    Some(LibraryVersion::from_raw(&raw::LibraryVersion::parse(&mut data.try_get(addr..)?)?)?)
                }
            },
            xapi_library_version: {
                if raw.xapi_library_version_addr == 0 {
                    None
                } else {
                    let addr = raw.rel_addr(raw.xapi_library_version_addr);
                    Some(LibraryVersion::from_raw(&raw::LibraryVersion::parse(&mut data.try_get(addr..)?)?)?)
                }
            },
            logo_bitmap: {
                let addr = raw.rel_addr(raw.logo_bitmap_addr);
                // Prevent overflows during address computation
                let end = addr.checked_add(raw.logo_bitmap_size)
                    .ok_or_else(|| Error::addr_overflow(addr, raw.logo_bitmap_size))?;
                LogoBitmap::decode(data.try_get(addr..end)?)?
            }
        })
    }

    /// Get a reference to the included certificate.
    ///
    /// The certificate contains various information about the game (such as its
    /// title, region and ratings), as well as a few signing keys.
    pub fn cert(&self) -> &Certificate {
        &self.cert
    }

    /// Get a reference to the logo bitmap included in the XBE image.
    ///
    /// In most cases, this is unfortunately just the Microsoft logo instead of
    /// a game-specific one.
    pub fn logo(&self) -> &LogoBitmap {
        &self.logo_bitmap
    }

    /// Init / Loader flags.
    pub fn init_flags(&self) -> &InitFlags {
        &self.init_flags
    }

    /// Number of bytes of stack space to commit to RAM when loading the XBE.
    ///
    /// The *reserved* amount of stack space doesn't seem to be configured in
    /// the header.
    pub fn stack_commit(&self) -> u32 {
        self.pe_stack_commit
    }

    /// Number of bytes to reserve for the process heap.
    ///
    /// Reserved memory exists as virtual memory, but has no backing storage in
    /// RAM or swap. Instead, backing memory is allocated when a page is first
    /// used.
    ///
    /// The heap can also be configured to have a subset of its memory committed
    /// at load time using `heap_commit`.
    pub fn heap_reserve(&self) -> u32 {
        self.pe_heap_reserve
    }

    /// Number of heap bytes to commit to RAM at load time.
    pub fn heap_commit(&self) -> u32 {
        self.pe_heap_commit
    }

    /// Return the decoded entry point, assuming it was encoded for the given
    /// image kind (retail or debug Xbox).
    ///
    /// Also see [`Xbe::entry_point`], which is easier to use and determines the
    /// image kind automatically.
    ///
    /// [`Xbe::entry_point`]: struct.Xbe.html#method.entry_point
    pub fn entry_point(&self, image_kind: ImageKind) -> u32 {
        match image_kind {
            ImageKind::Debug => self.entry_point ^ ENTRY_XOR_DEBUG,
            ImageKind::Retail => self.entry_point ^ ENTRY_XOR_RETAIL,
        }
    }

    /// Returns the address of the kernel thunk table, assuming it was encoded
    /// for the given image kind (retail or debug Xbox).
    ///
    /// This is the address in virtual memory in the XBE's address space after
    /// all sections have been mapped to their requested virtual addresses.
    /// Most likely, it points directly at the beginning of the `.rdata`
    /// section.
    ///
    /// Note that many freely available demos and ROMs have this encoded using
    /// the debug mask instead of the retail mask.
    ///
    /// Also see [`Xbe::kernel_thunk_table`], which automatically determines the
    /// image kind and returns an already decoded thunk table.
    ///
    /// [`Xbe::kernel_thunk_table`]: struct.Xbe.html#method.kernel_thunk_table
    pub fn kernel_thunk_addr(&self, image_kind: ImageKind) -> u32 {
        match image_kind {
            ImageKind::Debug => self.kernel_thunk_addr ^ THUNK_XOR_DEBUG,
            ImageKind::Retail => self.kernel_thunk_addr ^ THUNK_XOR_RETAIL,
        }
    }

    /// Scans the section headers to find a section that contains the given
    /// virtual address.
    pub fn find_section_containing(&self, virt_addr: u32) -> Option<&SectionHeader> {
        self.section_headers.iter().find(|section| {
            *section.virt_range().start() <= virt_addr && *section.virt_range().end() >= virt_addr
        })
    }

    /// Scans the section headers for a section whose virtual address range
    /// contains the given address.
    ///
    /// Returns an `AddressInfo` object for debug printing the address, its
    /// containing section and its offset into the section.
    // TODO rename this?
    pub fn find_address_info(&self, virt_addr: u32) -> AddressInfo {
        let section = self.find_section_containing(virt_addr);
        let offset = if let Some(s) = section {
            virt_addr - s.virt_range().start()
        } else {
            0
        };

        AddressInfo {
            section,
            offset,
            address: virt_addr,
        }
    }

    /// Translates a virtual address to an offset into the XBE image.
    ///
    /// Returns `None` if the virtual address isn't inside any section of this
    /// XBE.
    ///
    /// Note that a section doesn't necessarily span it's whole virtual range.
    fn translate_virt_addr(&self, virt_addr: u32) -> Option<u32> {
        let section = self.find_section_containing(virt_addr)?;
        let vstart = *section.virt_range().start();
        let offset = virt_addr - vstart;
        let raw = section.raw_range();
        let raw_pos = raw.start().checked_add(offset)?;
        if raw_pos > *raw.end() {
            None    // section backing data smaller than virt. range
        } else {
            Some(raw_pos)
        }
    }
}

bitflags! {
    /// Values of the `init_flags` field in the header.
    pub struct InitFlags: u32 {
        const MOUNT_UTILITY_DRIVE  = 0x00000001;
        const FORMAT_UTILITY_DRIVE = 0x00000002;
        /// Limit devkit runtime to 64 MB of RAM.
        const LIMIT_64_MEGABYTES   = 0x00000004;
        const DONT_SETUP_HARDDISK  = 0x00000008;
    }
}

/// Info for a virtual address in the XBE memory map.
///
/// This is suitable for user display, but probably most useful as a crash or
/// debug helper since the `Display` output is very technical. Using `{:?}` is
/// not recommended.
///
/// Note that if the address is not inside one of the static XBE sections, the
/// output will be pretty useless. It is recommended to check the address
/// against system-managed resources before using this (eg. stack, heap, kernel
/// space).
#[derive(Debug)]
pub struct AddressInfo<'a> {
    /// Section header of the section `address` is located in (if any).
    section: Option<&'a SectionHeader>,
    /// Offset from start of section. 0 if not in a section.
    offset: u32,
    /// Virtual address to look up.
    address: u32,
}

impl<'a> AddressInfo<'a> {
    /// The virtual address for which this information was determined.
    pub fn virt_addr(&self) -> u32 {
        self.address
    }

    /// Returns the section containing the virtual address.
    pub fn section(&self) -> Option<&SectionHeader> {
        self.section
    }
}

impl<'a> fmt::Display for AddressInfo<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(section) = self.section {
            let virt_range = section.virt_range();
            let raw_range = section.raw_range();
            let (vstart, vend) = (virt_range.start(), virt_range.end());
            let (rstart, rend) = (raw_range.start(), raw_range.end());

            write!(f,
                   "address {:#08X} is {:#X} Bytes into section '{}' spanning virtual addresses {:#08X}..={:#08X} and raw addresses {:#08X}..={:#08X}",
                   self.address, self.offset, section.name(), vstart, vend, rstart, rend
            )
        } else {
            write!(f,
                   "address {:#08X} is not inside any static XBE section",
                   self.address
            )
        }
    }
}

/// Iterator over the sections in an XBE image.
pub struct Sections<'a> {
    headers: std::slice::Iter<'a, SectionHeader>,
    image: &'a [u8],
}

impl<'a> Sections<'a> {
    fn new(headers: &'a [SectionHeader], image: &'a [u8]) -> Self {
        Self {
            headers: headers.iter(),
            image,
        }
    }
}

impl<'a> Iterator for Sections<'a> {
    type Item = Section<'a>;

    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        let header = self.headers.next()?;

        Some(Section {
            data: self.image.try_get(header.raw_range())
                .expect("raw_range not in image bounds (internal error)"),
            header,
        })
    }
}

/// A section pointing into the image's memory.
///
/// This contains all information needed to set up the section's virtual memory.
pub struct Section<'a> {
    /// Bytes making up the section data in the image.
    data: &'a [u8],
    header: &'a SectionHeader,
}

impl<'a> Section<'a> {
    /// Get the section header, which specifies where and how to map the data.
    pub fn header(&self) -> &SectionHeader {
        self.header
    }

    /// Returns the XBE image data to fill this section with.
    ///
    /// This is the data in the image file and might not suffice to fill all the
    /// virtual memory occupied by the section.
    // TODO: what happens then?
    pub fn data(&self) -> &[u8] {
        self.data
    }
}

/// A section header in an XBE file.
///
/// All sections specified by the section headers are mapped into the processes
/// virtual memory by the loader. The section header specifies where and how
/// that mapping happens.
#[derive(Debug)]
pub struct SectionHeader {
    section_flags: SectionFlags,
    virt_range: RangeInclusive<u32>,
    raw_range: RangeInclusive<u32>,
    name: String,
}

impl SectionHeader {
    fn from_raw(header: &raw::Header, raw: &raw::SectionHeader, data: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            section_flags: {
                let flags = SectionFlags::from_bits_truncate(raw.section_flags);
                if flags.bits() != raw.section_flags {
                    warn!("unknown section flags: known flags: {:#X}, raw flags: {:#X}", flags.bits(), raw.section_flags);
                }
                flags
            },
            virt_range: {
                raw.virt_addr.checked_add(raw.virt_size)
                    .ok_or_else(|| Error::addr_overflow(raw.virt_addr, raw.virt_size))?;

                raw.virt_addr ..= raw.virt_addr+raw.virt_size
            },
            raw_range: {
                raw.raw_addr.checked_add(raw.raw_size)
                    .ok_or_else(|| Error::addr_overflow(raw.raw_addr, raw.raw_size))?;

                let range = raw.raw_addr ..= raw.raw_addr+raw.raw_size;
                data.try_get(range.clone())?;   // check if in-bounds
                range
            },
            name: {
                let name_addr = header.rel_addr(raw.section_name_addr);
                data.try_get(name_addr..)?.iter()
                    .take_while(|b| **b != 0)
                    .map(|b| *b as char)
                    .collect::<String>()
            },
        })
    }

    /// The range of virtual addresses this section should be mapped into.
    pub fn virt_range(&self) -> RangeInclusive<u32> {
        self.virt_range.clone()
    }

    /// The memory range inside the XBE image to be mapped to the virtual range.
    ///
    /// The returned range is guaranteed to be inside the bounds of the XBE
    /// image.
    // FIXME is this the *file* range or does it take the base addr into acct?
    pub fn raw_range(&self) -> RangeInclusive<u32> {
        self.raw_range.clone()
    }

    /// Returns the section's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Gets the section flags that configure *how* the section should be
    /// mapped.
    pub fn flags(&self) -> &SectionFlags {
        &self.section_flags
    }
}

bitflags! {
    /// Flags used for the `section_flags` field of `SectionHeader`.
    ///
    /// Specifies properties that affect the way the virtual memory map is
    /// created or other properties of the section.
    pub struct SectionFlags: u32 {
        /// The section should be mapped as writeable.
        const WRITABLE            = 0x00000001;
        /// Speculation: Hints to the kernel that this section should be
        /// preloaded from disk instead of demand-paged into memory on first
        /// use.
        const PRELOAD             = 0x00000002;
        /// The section should be mapped as executable.
        const EXECUTABLE          = 0x00000004;
        const INSERTED_FILE       = 0x00000008;
        /// Speculation: Makes the first 4K page in the section read only to
        /// make it act like a guard page.
        const HEAD_PAGE_READ_ONLY = 0x00000010;
        /// Speculation: Makes the last 4K page in the section read only to
        /// make it act like a guard page.
        const TAIL_PAGE_READ_ONLY = 0x00000020;
    }
}

/// Describes the version of a library to link with.
#[derive(Debug)]
pub struct LibraryVersion {
    name: String,
    major_version: u16,
    minor_version: u16,
    build_version: u16,
    flags: LibraryFlags,
}

impl LibraryVersion {
    fn from_raw(raw: &raw::LibraryVersion) -> Result<Self, Error> {
        Ok(Self {
            name: {
                let name_end = raw.library_name.iter().position(|b| *b == 0).unwrap_or(0);

                #[cfg_attr(feature = "cargo-clippy", allow(indexing_slicing))]
                let bytes = &raw.library_name[..name_end];

                String::from_utf8_lossy(bytes).to_string()
            },
            major_version: raw.major_version,
            minor_version: raw.minor_version,
            build_version: raw.build_version,
            flags: {
                let flags = LibraryFlags::from_bits_truncate(raw.library_flags);
                if flags.bits() != raw.library_flags {
                    warn!("unknown library flags: known flags: {:#X}, raw flags: {:#X}", flags.bits(), raw.library_flags);
                }
                flags
            }
        })
    }

    /// Returns the flags that specify further properties of the library.
    pub fn flags(&self) -> &LibraryFlags {
        &self.flags
    }

    /// Returns the library's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the version triplet of the library.
    ///
    /// `(major, minor, build)`.
    pub fn version(&self) -> (u16, u16, u16) {
        (self.major_version, self.minor_version, self.build_version)
    }
}

bitflags! {
    /// Flags used in the `library_flags` field of `LibraryVersion`.
    pub struct LibraryFlags: u16 {
        const QFE_VERSION = 0x1FFF; // 13-bit value
        /// 2-bit value:
        ///
        /// * 0b00 = No
        /// * 0b01 = Possibly
        /// * 0b10 = Yes
        /// * 0b11 = Presumably an illegal value
        const APPROVED    = 0x6000; // 2-bit value
        const DEBUG_BUILD = 0x8000;
    }
}

/// A decoded thunk table.
///
/// The thunk table lists kernel symbols to be imported into the XBE process.
/// Each symbol is represented by an import ID according to [this table]. The
/// loader replaces the 32-bit import IDs by the address of the symbol.
///
/// [this table]: http://xboxdevwiki.net/Kernel#Kernel_exports
#[derive(Debug)]
pub struct KernelThunkTable {
    /// The kernel symbol import IDs.
    import_ids: Vec<ImportId>,
    /// Virtual address range containing the import IDs (not counting the
    /// terminating zero).
    virt_range: RangeInclusive<u32>,
    /// Image-relative address range containing the import IDs (not counting the
    /// terminating zero).
    image_range: RangeInclusive<u32>,
    /// Size of the import IDs in bytes (again not counting the terminating
    /// zero).
    bytes: u32,
}

impl KernelThunkTable {
    /// Decode thunk table from the XBE image at an offset.
    ///
    /// Returns an error if the table isn't properly terminated or is out of
    /// bounds.
    ///
    /// # Parameters
    ///
    /// * `data`: The raw XBE image data.
    /// * `virt_addr`: Virtual address of the thunk table.
    /// * `raw_addr`: Image-relative address of the thunk table (offset into
    ///   `data`).
    fn from_raw(data: &[u8], virt_addr: u32, raw_addr: u32) -> Result<Self, Error> {
        let mut table = data.try_get(raw_addr..)?;
        let mut imports = Vec::new();
        loop {
            let import = table.read_u32::<LE>()?;
            if import == 0 {
                // Terminated
                break;
            }

            // mask off the significant bits
            let import = import & 0x1FF;    // max = 511
            imports.push(ImportId(import));
        }

        let num_imports = imports.len() as u32; // can't fail due to XBE size restriction
        Ok(Self {
            import_ids: imports,
            virt_range: virt_addr ..= virt_addr + num_imports * 4,
            image_range: raw_addr ..= raw_addr + num_imports * 4,
            bytes: num_imports * 4,
        })
    }

    /// Returns the symbol import IDs in this thunk table.
    pub fn import_ids(&self) -> &[ImportId] {
        &self.import_ids
    }

    /// Returns the virtual address at which this thunk table starts.
    pub fn virt_addr(&self) -> u32 {
        *self.virt_range.start()
    }

    /// Returns the length of the thunk table in bytes (not counting the
    /// terminating null entry).
    pub fn len(&self) -> u32 {
        self.bytes
    }
}

/// A kernel symbol import stored in the thunk table.
///
/// See [`KernelThunkTable`](struct.KernelThunkTable.html).
pub struct ImportId(u32);

impl ImportId {
    /// Returns the imported symbol as an index into the [kernel export table].
    ///
    /// Note that the index might be out of bounds of that table. In that case,
    /// an unknown symbol is referenced.
    ///
    /// [kernel export table]: http://xboxdevwiki.net/Kernel#Kernel_exports
    pub fn index(&self) -> u32 {
        self.0
    }

    /// Returns the name of the referenced symbol.
    pub fn name(&self) -> &str {
        kernel_symbols::KERNEL_SYMBOLS.get(self.0 as usize).unwrap_or(&"<unknown import ID>")
    }
}

impl fmt::Debug for ImportId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} -> {}", self.index(), self.name())
    }
}
