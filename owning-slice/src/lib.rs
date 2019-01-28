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
    /// Equivalent to `self[start..start+length]` but by value
    pub fn into_slice(self, start: I, length: I) -> OwningSlice<B, I> {
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

    /// Equivalent to `self[start..]` but by value
    pub fn into_slice_from(self, start: I) -> OwningSlice<B, I> {
        let len = self.len();
        let ustart = start.into();

        assert!(ustart <= len);

        OwningSlice {
            buffer: self.buffer,
            start: self.start + start,
            length: self.length - start,
        }
    }

    /// Equivalent to `self[..end]` but by value
    pub fn into_slice_to(self, end: I) -> OwningSlice<B, I> {
        let len = self.len();
        let uend = end.into();

        assert!(uend <= len);

        OwningSlice {
            buffer: self.buffer,
            start: self.start,
            length: end,
        }
    }

    /// Truncates the owning slice to the specified length
    pub fn truncate(&mut self, len: I) {
        if len < self.length {
            self.length = len;
        }
    }

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
    type Output = OwningSlice<B, I>;

    fn into_slice(self, start: I, length: I) -> Self::Output {
        self.into_slice(start, length)
    }
}

impl<B, I> IntoSliceFrom<I> for OwningSlice<B, I>
where
    B: AsSlice,
    I: sealed::Index,
{
    type OutputF = OwningSlice<B, I>;

    fn into_slice_from(self, start: I) -> Self::OutputF {
        self.into_slice_from(start)
    }
}

impl<B, I> IntoSliceTo<I> for OwningSlice<B, I>
where
    B: AsSlice,
    I: sealed::Index,
{
    type OutputT = OwningSlice<B, I>;

    fn into_slice_to(self, end: I) -> Self::OutputT {
        self.into_slice_to(end)
    }
}

impl<B, I> Truncate<I> for OwningSlice<B, I>
where
    B: AsSlice,
    I: sealed::Index,
{
    fn truncate(&mut self, len: I) {
        self.truncate(len)
    }
}
