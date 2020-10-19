//! Contains the certificate data structures.
//!
//! The certificate contains a lot of metadata for the game (such as the
//! human-readable name of the title, which is useful for display purposes).

use crate::error::Error;
use crate::raw;

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A certificate included in an XBE image.
///
/// The certificate contains various information about the game (such as its
/// title, region and ratings), as well as a few signing keys.
///
/// Returned by [`Header::cert`].
///
/// [`Header::cert`]: ../struct.Header.html#method.cert
#[derive(Debug)]
pub struct Certificate {
    /// Certificate size in Bytes.
    size: u32,
    /// Creation time of the certificate.
    time_date: SystemTime,
    /// The primary title identifier code.
    title_id: u32,
    /// Title name of the application.
    title_name: String,
    /// Array of alternative `title_id`s (or zeros).
    alt_title_ids: [u32; 16],
    /// Allowed media types.
    ///
    /// Known flags in this bitmask are listed as `MediaTypes`.
    allowed_media: MediaTypes,
    /// See `GameRegion`.
    game_region: GameRegion,
    game_ratings: u32, // FIXME format unknown
    disk_number: u32,
    version: u32,
    lan_key: Key,
    signature_key: Key,
    /// Alternative signature keys.
    alt_signature_keys: [Key; 16],
}

impl Certificate {
    pub(crate) fn from_raw(raw: &raw::Certificate) -> Result<Self, Error> {
        Ok(Self {
            size: raw.size,
            time_date: UNIX_EPOCH + Duration::from_secs(raw.time_date.into()),
            title_id: raw.title_id,
            title_name: {
                let s = String::from_utf16_lossy(&raw.title_name.0);
                s.trim_end_matches('\0').to_string()
            },
            alt_title_ids: raw.alt_title_ids,
            allowed_media: {
                let flags = MediaTypes::from_bits_truncate(raw.allowed_media);
                if flags.bits() != raw.allowed_media {
                    warn!(
                        "unknown media type flags: known flags: {:#X}, raw flags: {:#X}",
                        flags.bits(),
                        raw.allowed_media
                    );
                }
                flags
            },
            game_region: {
                let flags = GameRegion::from_bits_truncate(raw.game_region);
                if flags.bits() != raw.game_region {
                    warn!(
                        "unknown game region flags: known flags: {:#X}, raw flags: {:#X}",
                        flags.bits(),
                        raw.game_region
                    );
                }
                flags
            },
            game_ratings: raw.game_ratings,
            disk_number: raw.disk_number,
            version: raw.version,
            lan_key: Key(raw.lan_key),
            signature_key: Key(raw.signature_key),
            alt_signature_keys: {
                let mut keys = [Key([0; 16]); 16];
                for (dest, src) in keys.iter_mut().zip(raw.alt_signature_keys.iter()) {
                    *dest = Key(*src);
                }
                keys
            },
        })
    }

    /// Returns the time at which this certificate was created.
    pub fn creation_time(&self) -> &SystemTime {
        &self.time_date
    }

    pub fn title_name(&self) -> &str {
        &self.title_name
    }

    /// Returns the primary title ID of the game.
    ///
    /// For homebrew, this might be 0.
    pub fn title_id(&self) -> u32 {
        self.title_id
    }

    /// Returns the alternate title IDs of the game.
    ///
    /// Likely, not all of these are used, with the rest being set to 0.
    pub fn alt_title_ids(&self) -> &[u32; 16] {
        &self.alt_title_ids
    }

    /// Bit flags indicating the allowed media types for distribution of the
    /// game.
    pub fn allowed_media(&self) -> &MediaTypes {
        &self.allowed_media
    }

    /// Bit flags of regions in which this game is available.
    pub fn game_region(&self) -> &GameRegion {
        &self.game_region
    }

    /// Disk this certificate was created for. Likely 0.
    pub fn disk_number(&self) -> u32 {
        self.disk_number
    }

    /// Certificate version / revision.
    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn lan_key(&self) -> &Key {
        &self.lan_key
    }

    pub fn signature_key(&self) -> &Key {
        &self.signature_key
    }

    pub fn alt_signature_keys(&self) -> &[Key; 16] {
        &self.alt_signature_keys
    }
}

bitflags! {
    /// Media type mask used for the `allowed_media` field in `Certificate`.
    pub struct MediaTypes: u32 {
        const HARD_DISK           = 0x00000001;
        const DVD_X2              = 0x00000002;
        const DVD_CD              = 0x00000004;
        const CD                  = 0x00000008;
        const DVD_5_RO            = 0x00000010;
        const DVD_9_RO            = 0x00000020;
        const DVD_5_RW            = 0x00000040;
        const DVD_9_RW            = 0x00000080;
        const DONGLE              = 0x00000100;
        const MEDIA_BOARD         = 0x00000200;
        const NONSECURE_HARD_DISK = 0x40000000;
        const NONSECURE_MODE      = 0x80000000;
    }
}

bitflags! {
    /// Region flags used in the `game_region` field of `Certificate`.
    pub struct GameRegion: u32 {
        const NA            = 0x00000001;
        const JAPAN         = 0x00000002;
        const REST_OF_WORLD = 0x00000004;
        const MANUFACTURING = 0x80000000;
    }
}

/// 16-Byte signing key.
///
/// This struct exists to make the debug output nicer.
#[derive(Copy, Clone)]
pub struct Key(pub [u8; 16]);

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x")?;
        for b in &self.0 {
            write!(f, "{:02X}", b)?;
        }
        Ok(())
    }
}
