#![deny(warnings)]
#![no_std]

mod from;
mod sealed;
#[cfg(test)]
mod tests;
mod to;
mod traits;

use core::{ops, slice};

use as_slice::{AsMutSlice, AsSlice};
use stable_deref_trait::StableDeref;

pub use {
    from::OwningSliceFrom,
    to::OwningSliceTo,
    traits::{IntoSlice, IntoSliceFrom, IntoSliceTo, Truncate},
};

/// Owning slice of a `BUFFER`
#[derive(Clone, Copy)]
pub struct OwningSlice<BUFFER, INDEX>
where
    BUFFER: AsSlice,
    INDEX: sealed::Index,
{
    pub(crate) buffer: BUFFER,
    pub(crate) start: INDEX,
    pub(crate) length: INDEX,
}

/// Equivalent to `buffer[start..start+length]` but by value
#[allow(non_snake_case)]
pub fn OwningSlice<B, I>(buffer: B, start: I, length: I) -> OwningSlice<B, I>
where
    B: AsSlice,
    I: sealed::Index,
{
    let blen = buffer.as_slice().len();
    let ustart = start.into();
    let ulength = length.into();

    assert!(ustart + ulength <= blen);

    OwningSlice {
        buffer,
        start,
        length,
    }
}

impl<B, I> OwningSlice<B, I>
where
    B: AsSlice,
    I: sealed::Index,
{
    /// Destroys the owning slice and returns the original buffer
    pub fn unslice(self) -> B {
        self.buffer
    }
}

impl<B, I> AsSlice for OwningSlice<B, I>
where
    B: AsSlice,
    I: sealed::Index,
{
    type Element = B::Element;

    fn as_slice(&self) -> &[B::Element] {
        unsafe {
            let p = self.buffer.as_slice().as_ptr().add(self.start.into());
            let len = self.length.into();

            slice::from_raw_parts(p, len)
        }
    }
}

impl<B, I> AsMutSlice for OwningSlice<B, I>
where
    B: AsMutSlice,
    I: sealed::Index,
{
    fn as_mut_slice(&mut self) -> &mut [B::Element] {
        unsafe {
            let p = self
                .buffer
                .as_mut_slice()
                .as_mut_ptr()
                .add(self.start.into());
            let len = self.length.into();

            slice::from_raw_parts_mut(p, len)
        }
    }
}

impl<B, I> ops::Deref for OwningSlice<B, I>
where
    B: AsSlice,
    I: sealed::Index,
{
    type Target = [B::Element];

    fn deref(&self) -> &[B::Element] {
        self.as_slice()
    }
}

impl<B, I> ops::DerefMut for OwningSlice<B, I>
where
    B: AsMutSlice,
    I: sealed::Index,
{
    fn deref_mut(&mut self) -> &mut [B::Element] {
        self.as_mut_slice()
    }
}

impl<B, I> From<OwningSliceFrom<B, I>> for OwningSlice<B, I>
where
    B: AsSlice,
    I: sealed::Index,
{
    fn from(slice: OwningSliceFrom<B, I>) -> OwningSlice<B, I> {
        let length = I::from_usize(slice.len());

        OwningSlice {
            buffer: slice.buffer,
            start: slice.start,
            length,
        }
    }
}

impl<B, I> From<OwningSliceTo<B, I>> for OwningSlice<B, I>
where
    B: AsSlice,
    I: sealed::Index,
{
    fn from(slice: OwningSliceTo<B, I>) -> OwningSlice<B, I> {
        OwningSlice {
            buffer: slice.buffer,
            start: I::zero(),
            length: slice.end,
        }
    }
}

unsafe impl<B, I> StableDeref for OwningSlice<B, I>
where
    B: AsSlice + StableDeref,
    I: sealed::Index,
{
}

impl<B, I> IntoSlice<I> for OwningSlice<B, I>
where
    B: AsSlice,
    I: sealed::Index,
{
    type Slice = OwningSlice<B, I>;

    fn into_slice(self, start: I, length: I) -> Self::Slice {
        let len = self.len();
        let ustart = start.into();
        let ulength = length.into();

        assert!(ustart + ulength <= len);

        OwningSlice {
            buffer: self.buffer,
            start: self.start + start,
            length,
        }
    }
}

impl<B> IntoSlice<u16> for OwningSlice<B, u8>
where
    B: AsSlice,
{
    type Slice = OwningSlice<B, u8>;

    fn into_slice(self, start: u16, length: u16) -> Self::Slice {
        let len = self.len();

        assert!(usize::from(start) + usize::from(length) <= len);

        // NOTE(cast) start, length < self.len() (self.length) <= u8::MAX
        OwningSlice {
            buffer: self.buffer,
            start: self.start + start as u8,
            length: length as u8,
        }
    }
}

impl<B> IntoSlice<u8> for OwningSlice<B, u16>
where
    B: AsSlice,
{
    type Slice = OwningSlice<B, u16>;

    fn into_slice(self, start: u8, length: u8) -> Self::Slice {
        let len = self.len();

        assert!(usize::from(start) + usize::from(length) <= len);

        OwningSlice {
            buffer: self.buffer,
            start: self.start + u16::from(start),
            length: u16::from(length),
        }
    }
}

impl<B, I> IntoSliceFrom<I> for OwningSlice<B, I>
where
    B: AsSlice,
    I: sealed::Index,
{
    type SliceFrom = OwningSlice<B, I>;

    fn into_slice_from(self, start: I) -> Self::SliceFrom {
        let len = self.len();
        let ustart = start.into();

        assert!(ustart <= len);

        OwningSlice {
            buffer: self.buffer,
            start: self.start + start,
            length: self.length - start,
        }
    }
}

impl<B> IntoSliceFrom<u16> for OwningSlice<B, u8>
where
    B: AsSlice,
{
    type SliceFrom = OwningSlice<B, u8>;

    fn into_slice_from(self, start: u16) -> Self::SliceFrom {
        let len = self.len();

        assert!(usize::from(start) <= len);

        // NOTE(cast) start < len (self.length) <= u8::MAX
        OwningSlice {
            buffer: self.buffer,
            start: self.start + start as u8,
            length: self.length - start as u8,
        }
    }
}

impl<B> IntoSliceFrom<u8> for OwningSlice<B, u16>
where
    B: AsSlice,
{
    type SliceFrom = OwningSlice<B, u16>;

    fn into_slice_from(self, start: u8) -> Self::SliceFrom {
        let len = self.len();

        assert!(usize::from(start) <= len);

        OwningSlice {
            buffer: self.buffer,
            start: self.start + u16::from(start),
            length: self.length - u16::from(start),
        }
    }
}

impl<B, I> IntoSliceTo<I> for OwningSlice<B, I>
where
    B: AsSlice,
    I: sealed::Index,
{
    type SliceTo = OwningSlice<B, I>;

    fn into_slice_to(self, end: I) -> Self::SliceTo {
        let len = self.len();
        let uend = end.into();

        assert!(uend <= len);

        OwningSlice {
            buffer: self.buffer,
            start: self.start,
            length: end,
        }
    }
}

impl<B> IntoSliceTo<u16> for OwningSlice<B, u8>
where
    B: AsSlice,
{
    type SliceTo = OwningSlice<B, u8>;

    fn into_slice_to(self, end: u16) -> Self::SliceTo {
        let len = self.len();

        assert!(usize::from(end) <= len);

        OwningSlice {
            buffer: self.buffer,
            start: self.start,
            // NOTE(cast) end <= len (self.length) <= u8::MAX
            length: end as u8,
        }
    }
}

impl<B> IntoSliceTo<u8> for OwningSlice<B, u16>
where
    B: AsSlice,
{
    type SliceTo = OwningSlice<B, u16>;

    fn into_slice_to(self, end: u8) -> Self::SliceTo {
        let len = self.len();

        assert!(usize::from(end) <= len);

        OwningSlice {
            buffer: self.buffer,
            start: self.start,
            // NOTE(cast) end <= len <= u8::MAX
            length: u16::from(end),
        }
    }
}

impl<B, I> Truncate<I> for OwningSlice<B, I>
where
    B: AsSlice,
    I: sealed::Index,
{
    fn truncate(&mut self, len: I) {
        if len < self.length {
            self.length = len;
        }
    }
}

impl<B> Truncate<u16> for OwningSlice<B, u8>
where
    B: AsSlice,
{
    fn truncate(&mut self, len: u16) {
        if len < u16::from(self.length) {
            // NOTE(cast) `len < self.length <= u8::MAX`
            self.length = len as u8;
        }
    }
}

impl<B> Truncate<u8> for OwningSlice<B, u16>
where
    B: AsSlice,
{
    fn truncate(&mut self, len: u8) {
        if u16::from(len) < self.length {
            self.length = u16::from(len);
        }
    }
}
