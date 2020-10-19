use crate::error::Error;

use std::fmt;
use std::ops::{Deref, DerefMut, Range, RangeFrom, RangeInclusive, RangeTo};

/// Slice extension methods.
pub trait SliceExt<T> {
    /// Tries to obtain an element or subslice of `self`, returning an
    /// appropriate error if the range is out of bounds.
    fn try_get<R>(&self, range: R) -> Result<&R::Output, Error>
    where
        R: SliceIndex<T>;
}

impl<T> SliceExt<T> for [T] {
    fn try_get<R>(&self, range: R) -> Result<&R::Output, Error>
    where
        R: SliceIndex<T>,
    {
        range.get(self)
    }
}

/// A type that can be used to index a slice.
pub trait SliceIndex<T> {
    type Output: ?Sized;

    /// Get the element or subslice of `slice` at the position indicated by `self`.
    fn get(self, slice: &[T]) -> Result<&Self::Output, Error>;
}

// Support only `u32` indexing. This works on all 32-bit+ systems and is
// convenient since XBE images use 32-bit addresses for everything.
// Care must be taken when calculating addresses as that might lead to overflows
// when using `u32`.

impl<T> SliceIndex<T> for u32 {
    type Output = T;

    fn get(self, slice: &[T]) -> Result<&T, Error> {
        slice.get(self as usize).ok_or_else(|| {
            Error::Malformed(format!(
                "pointer points outside XBE image (index {} out of bounds of slice with length {})",
                self,
                slice.len()
            ))
        })
    }
}

impl<T> SliceIndex<T> for Range<u32> {
    type Output = [T];

    fn get(self, slice: &[T]) -> Result<&[T], Error> {
        slice
            .get(self.start as usize..self.end as usize)
            .ok_or_else(|| {
                Error::Malformed(format!(
            "pointer points outside XBE image (range {}..{} out of bounds of slice with length {})",
            self.start, self.end, slice.len()
        ))
            })
    }
}

impl<T> SliceIndex<T> for RangeInclusive<u32> {
    type Output = [T];

    fn get(self, slice: &[T]) -> Result<&[T], Error> {
        slice
            .get(*self.start() as usize..=*self.end() as usize)
            .ok_or_else(|| {
                Error::Malformed(format!(
            "pointer points outside XBE image (range {}..{} out of bounds of slice with length {})",
            self.start(), self.end(), slice.len()
        ))
            })
    }
}

impl<T> SliceIndex<T> for RangeFrom<u32> {
    type Output = [T];

    fn get(self, slice: &[T]) -> Result<&[T], Error> {
        slice.get(self.start as usize..).ok_or_else(|| {
            Error::Malformed(format!(
            "pointer points outside XBE image (range {}.. out of bounds of slice with length {})",
            self.start, slice.len()
        ))
        })
    }
}

impl<T> SliceIndex<T> for RangeTo<u32> {
    type Output = [T];

    fn get(self, slice: &[T]) -> Result<&[T], Error> {
        slice.get(..self.end as usize).ok_or_else(|| {
            Error::Malformed(format!(
            "pointer points outside XBE image (range ..{} out of bounds of slice with length {})",
            self.end, slice.len()
        ))
        })
    }
}

/// Wraps any value and suppresses its debug output when printed with `{:?}`.
pub struct NoDebug<T>(pub T);

impl<T> fmt::Debug for NoDebug<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("(debug output omitted)")
    }
}

impl<T> Deref for NoDebug<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> DerefMut for NoDebug<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T> From<T> for NoDebug<T> {
    fn from(t: T) -> Self {
        NoDebug(t)
    }
}
