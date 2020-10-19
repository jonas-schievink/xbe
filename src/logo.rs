//! Provides types and methods to decode the logo bitmap of an XBE file.

use crate::Error;

use byteorder::ReadBytesExt;
use std::fmt;

/// A 100x17 grayscale logo stored in the XBE file.
///
/// The logo can be retrieved using [`Xbe::logo`].
///
/// [`Xbe::logo`]: struct.Xbe.html#method.logo
pub struct LogoBitmap {
    /// Pixel value are from 0 - 15 (4 bit).
    pixels: [[u8; 100]; 17],
}

impl LogoBitmap {
    /// Decode the bitmap from compressed data in an XBE image.
    ///
    /// The encoding is a run-length encoding (RLE) with two different kinds of
    /// commands or "chunks", one sized 1 Byte, the other sized 2 Bytes. If the
    /// least significant bit of the next Byte is set, it's a 1-Byte chunk.
    /// Otherwise, the second-to-least significant bit must be set and it's a
    /// 2-Byte chunk. Graphically:
    ///
    /// ```notrust
    /// 1-Byte / 8-bit chunk:
    /// +----------+----------+---+
    /// |   Data   |  Length  | 1 |
    /// | (4 bits) | (3 bits) |   |
    /// +----------+----------+---+
    /// MSb                     LSb
    ///
    /// 2-Byte / 16-bit chunk:
    /// +----------+-----------+---+---+
    /// |   Data   |  Length   | 1 | 0 |
    /// | (4 bits) | (10 bits) |   |   |
    /// +----------+-----------+---+---+
    /// MSb                          LSb
    /// Second Byte      |    First Byte (Xbox is a Little Endian system)
    /// ```
    ///
    /// After decoding `length` and `data`, both chunk types work the same: The
    /// 4-bit `data` value describes a pixel value to use for the next `length`
    /// pixels in the output image. The output image is scanned line by line
    /// from left to right, and whenever we decode a chunk, we set the next
    /// `length` pixels to the `data` value.
    ///
    /// A `data` value of 0 is black, while a `data` value of 15 is the
    /// brightest color, white. In order to convert to full 8 bits of color
    /// depth, it might be attractive to just shift `data` to the left by 4
    /// bits. However, this would make a `data` value of 15 (`0b00001111`)
    /// convert to `0b11110000`, which is just 240 instead of the 255 we'd like
    /// to get, resulting in a darker than expected image.
    ///
    /// We can fix this by "stretching" the result proportional to the resulting
    /// color value (since we want to add nothing when the value is small, but
    /// a lot if the value gets large). The correct way to do this is by
    /// dividing the resulting grayscale value by 16 (the maximum value that can
    /// be encoded in `data`) and adding that onto the result we already have.
    ///
    /// (Note that this is assuming the Xbox does it properly - it might just
    /// use `data << 4` for the final 8-bit value)
    // FIXME: "stretching" wording can be simplified - we just copy the nibble to the high AND low half of the byte
    // Even more generically, we shift the N bits up to occupy the MSbs, then copy the highest bits
    // to the lowest that are now 0
    pub fn decode(mut bytes: &[u8]) -> Result<Self, Error> {
        let mut pixels = [[0; 100]; 17];

        debug!("{} bytes", bytes.len());

        {
            // Iterator over pixels in the image
            let mut pixel_iter = pixels.iter_mut().flat_map(|row| row.iter_mut());
            while let Some(chunk) = RleChunk::read(&mut bytes)? {
                trace!("{:?}", chunk);
                let (length, data) = (chunk.length(), chunk.data());

                // Now we have length and data, write `length` pixels to the buffer
                for _ in 0..length {
                    match pixel_iter.next() {
                        Some(pix) => *pix = data,
                        None => {
                            return Err(Error::Malformed(
                                "RLE encoding too long for bitmap buffer".to_string(),
                            ))
                        }
                    }
                }
            }

            if pixel_iter.next().is_some() {
                debug!("RLE data didn't cover whole image");
            }
        }

        Ok(LogoBitmap { pixels })
    }

    /// Converts this grayscale bitmap to a multiline string resembling ASCII
    /// art of the bitmap. Each character represents a pixel and is chosen to
    /// somewhat match its brightness.
    ///
    /// Note that the resulting text is distorted: The actual image is much
    /// thinner and wider. This is a consequence of using a character to
    /// represent each pixel.
    pub fn to_multiline_drawing(&self) -> String {
        self.pixels
            .iter()
            .map(display_row)
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Converts this image to a pixel buffer storing 8-bit grayscale pixels.
    ///
    /// The resulting buffer can be displayed to the user.
    ///
    /// The pixels are encoded in row-major order, meaning that the first 100
    /// bytes in the returned buffer are the color values of the first row of
    /// pixels, followed by 100 bytes for the second row.
    pub fn to_8bit_grayscale(&self) -> [u8; 100 * 17] {
        let mut buf = [0u8; 100 * 17];
        for (src, dest) in self
            .pixels
            .iter()
            .flat_map(|row| row.iter())
            .zip(&mut buf[..])
        {
            *dest = to_8bit(*src);
        }
        buf
    }
}

impl fmt::Debug for LogoBitmap {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut list = f.debug_list();

        for row in &self.pixels {
            list.entry(&display_row(row));
        }

        list.finish()
    }
}

fn to_8bit(b: u8) -> u8 {
    assert_eq!(b & 0x0f, b, "invalid 4-bit color value {:#X}", b);

    let mut out = b << 4;
    out += out / 16;
    out
}

fn byte_to_ascii_pixel(b: u8) -> char {
    assert_eq!(b & 0x0f, b, "invalid 4-bit color value {:#X}", b);

    let chars: [char; 16] = [
        ' ', '.', '-', ':', '~', '=', '+', '*', 'a', '!', '$', '&', '%', '@', 'M', 'W',
    ];
    *chars
        .get(b as usize)
        .expect("4-bit value out of range (should never happen)")
}

/// Convert an image row to an ASCII string representing each pixel with a char.
fn display_row(row: &[u8; 100]) -> String {
    row.iter().map(|b| byte_to_ascii_pixel(*b)).collect()
}

/// A run-length encoding chunk specifying a color value for a number of pixels.
enum RleChunk {
    Byte(u8),
    Word(u16),
}

impl RleChunk {
    /// Reads an RLE chunk from a byte stream.
    fn read(bytes: &mut &[u8]) -> Result<Option<Self>, Error> {
        let first = match bytes.read_u8() {
            Ok(b) => b,
            Err(_) => return Ok(None),
        };

        if first & 0x01 != 0 {
            // LSb set -> 8-bit chunk
            Ok(Some(RleChunk::Byte(first)))
        } else if first & 0x02 != 0 {
            // 2nd most LSb set -> 16-bit chunk
            let second = match bytes.read_u8() {
                Ok(b) => b,
                Err(_) => return Err(Error::Malformed("unexpected EOF".to_string())),
            };

            // second byte is MSB of the two (Xbox is LSB first). stitch them together.
            let word = (u16::from(second) << 8) | u16::from(first);
            Ok(Some(RleChunk::Word(word)))
        } else {
            // invalid encoding
            Err(Error::Malformed("invalid marker for RLE chunk".to_string()))
        }
    }

    /// The number of pixels to use the `data` value for (up to 10 bits).
    fn length(&self) -> u16 {
        match *self {
            RleChunk::Byte(b) => (u16::from(b) & 0b00001110) >> 1,
            RleChunk::Word(w) => (w & 0b00001111_11111100) >> 2,
        }
    }

    /// The 4-bit pixel value.
    fn data(&self) -> u8 {
        match *self {
            RleChunk::Byte(b) => (b & 0b11110000) >> 4,
            RleChunk::Word(w) => ((w & 0b11110000_00000000) >> 12) as u8,
        }
    }
}

impl fmt::Debug for RleChunk {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            RleChunk::Byte(b) => write!(
                f,
                "byte (raw {:08b}) {:04b} {:03b} 1",
                b,
                self.data(),
                self.length()
            ),
            RleChunk::Word(w) => write!(
                f,
                "word (raw {:016b}) {:04b} {:010b} 10",
                w,
                self.data(),
                self.length()
            ),
        }
    }
}
