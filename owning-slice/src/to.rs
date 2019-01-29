use core::{ops, slice};

use stable_deref_trait::StableDeref;

use crate::{
    sealed,
    traits::{IntoSlice, IntoSliceFrom, IntoSliceTo, Truncate},
    AsMutSlice, AsSlice, OwningSlice,
};

/// Owning slice of a `BUFFER` where `start == 0`
#[derive(Clone, Copy)]
pub struct OwningSliceTo<BUFFER, INDEX>
where
    BUFFER: AsSlice,
    INDEX: sealed::Index,
{
    pub(crate) buffer: BUFFER,
    pub(crate) end: INDEX,
}

/// Equivalent to `buffer[..end]` but by value
#[allow(non_snake_case)]
pub fn OwningSliceTo<B, I>(buffer: B, end: I) -> OwningSliceTo<B, I>
where
    B: AsSlice,
    I: sealed::Index,
{
    let slen = buffer.as_slice().len();
    let uend = end.into();

    assert!(uend <= slen);

    OwningSliceTo { buffer, end }
}

impl<B, I> OwningSliceTo<B, I>
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
            start,
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
            start,
            length: self.end - start,
        }
    }

    /// Equivalent to `self[..end]` but by value
    pub fn into_slice_to(self, end: I) -> OwningSliceTo<B, I> {
        let len = self.len();
        let uend = end.into();

        assert!(uend <= len);

        OwningSliceTo {
            buffer: self.buffer,
            end,
        }
    }

    /// Truncates the owning slice to the specified `len`
    pub fn truncate<L>(&mut self, len: L)
    where
        L: Into<I>,
    {
        let len = len.into();
        if len < self.end {
            self.end = len;
        }
    }

    /// Destroys the owning slice and returns the original buffer
    pub fn unslice(self) -> B {
        self.buffer
    }
}

impl<B, I> AsSlice for OwningSliceTo<B, I>
where
    B: AsSlice,
    I: sealed::Index,
{
    type Element = B::Element;

    fn as_slice(&self) -> &[B::Element] {
        unsafe {
            let p = self.buffer.as_slice().as_ptr();
            let len = self.end.into();

            slice::from_raw_parts(p, len)
        }
    }
}

impl<B, I> AsMutSlice for OwningSliceTo<B, I>
where
    B: AsMutSlice,
    I: sealed::Index,
{
    fn as_mut_slice(&mut self) -> &mut [B::Element] {
        unsafe {
            let p = self.buffer.as_mut_slice().as_mut_ptr();
            let len = self.end.into();

            slice::from_raw_parts_mut(p, len)
        }
    }
}

impl<B, I> ops::Deref for OwningSliceTo<B, I>
where
    B: AsSlice,
    I: sealed::Index,
{
    type Target = [B::Element];

    fn deref(&self) -> &[B::Element] {
        self.as_slice()
    }
}

impl<B, I> ops::DerefMut for OwningSliceTo<B, I>
where
    B: AsMutSlice,
    I: sealed::Index,
{
    fn deref_mut(&mut self) -> &mut [B::Element] {
        self.as_mut_slice()
    }
}

unsafe impl<B, I> StableDeref for OwningSliceTo<B, I>
where
    B: AsSlice + StableDeref,
    I: sealed::Index,
{
}

impl<B, I> IntoSlice<I> for OwningSliceTo<B, I>
where
    B: AsSlice,
    I: sealed::Index,
{
    type Output = OwningSlice<B, I>;

    fn into_slice(self, start: I, length: I) -> Self::Output {
        self.into_slice(start, length)
    }
}

impl<B, I> IntoSliceFrom<I> for OwningSliceTo<B, I>
where
    B: AsSlice,
    I: sealed::Index,
{
    type OutputF = OwningSlice<B, I>;

    fn into_slice_from(self, start: I) -> Self::OutputF {
        self.into_slice_from(start)
    }
}

impl<B, I> IntoSliceTo<I> for OwningSliceTo<B, I>
where
    B: AsSlice,
    I: sealed::Index,
{
    type OutputT = OwningSliceTo<B, I>;

    fn into_slice_to(self, end: I) -> Self::OutputT {
        self.into_slice_to(end)
    }
}

impl<B, I, L> Truncate<L> for OwningSliceTo<B, I>
where
    B: AsSlice,
    I: sealed::Index,
    L: Into<I>,
{
    fn truncate(&mut self, len: L) {
        self.truncate(len)
    }
}
