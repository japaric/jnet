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
    type Slice = OwningSlice<B, I>;

    fn into_slice(self, start: I, length: I) -> Self::Slice {
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
}

impl<B> IntoSlice<u16> for OwningSliceTo<B, u8>
where
    B: AsSlice,
{
    type Slice = OwningSlice<B, u8>;

    fn into_slice(self, start: u16, length: u16) -> Self::Slice {
        let len = self.len();

        assert!(usize::from(start) + usize::from(length) <= len);

        // NOTE(cast) start, length < self.len() (self.end) <= u8::MAX
        OwningSlice {
            buffer: self.buffer,
            start: start as u8,
            length: length as u8,
        }
    }
}

impl<B> IntoSlice<u8> for OwningSliceTo<B, u16>
where
    B: AsSlice,
{
    type Slice = OwningSlice<B, u16>;

    fn into_slice(self, start: u8, length: u8) -> Self::Slice {
        let len = self.len();

        assert!(usize::from(start) + usize::from(length) <= len);

        // NOTE(cast) start, length < self.len() (self.end) <= u8::MAX
        OwningSlice {
            buffer: self.buffer,
            start: u16::from(start),
            length: u16::from(length),
        }
    }
}

impl<B, I> IntoSliceFrom<I> for OwningSliceTo<B, I>
where
    B: AsSlice,
    I: sealed::Index,
{
    type SliceFrom = OwningSlice<B, I>;

    fn into_slice_from(self, start: I) -> Self::SliceFrom {
        let len = self.len();

        assert!(start.into() <= len);

        OwningSlice {
            buffer: self.buffer,
            start,
            length: self.end - start,
        }
    }
}

impl<B> IntoSliceFrom<u16> for OwningSliceTo<B, u8>
where
    B: AsSlice,
{
    type SliceFrom = OwningSlice<B, u8>;

    fn into_slice_from(self, start: u16) -> Self::SliceFrom {
        let len = self.len();

        assert!(usize::from(start) <= len);

        // NOTE(cast) start < self.len() (self.end) <= u8::MAX
        OwningSlice {
            buffer: self.buffer,
            start: start as u8,
            length: self.end - start as u8,
        }
    }
}

impl<B> IntoSliceFrom<u8> for OwningSliceTo<B, u16>
where
    B: AsSlice,
{
    type SliceFrom = OwningSlice<B, u16>;

    fn into_slice_from(self, start: u8) -> Self::SliceFrom {
        let len = self.len();

        assert!(usize::from(start) <= len);

        OwningSlice {
            buffer: self.buffer,
            start: u16::from(start),
            length: self.end - u16::from(start),
        }
    }
}

impl<B, I> IntoSliceTo<I> for OwningSliceTo<B, I>
where
    B: AsSlice,
    I: sealed::Index,
{
    type SliceTo = OwningSliceTo<B, I>;

    fn into_slice_to(self, end: I) -> Self::SliceTo {
        let len = self.len();

        assert!(end.into() <= len);

        OwningSliceTo {
            buffer: self.buffer,
            end,
        }
    }
}

impl<B> IntoSliceTo<u16> for OwningSliceTo<B, u8>
where
    B: AsSlice,
{
    type SliceTo = OwningSliceTo<B, u8>;

    fn into_slice_to(self, end: u16) -> Self::SliceTo {
        let len = self.len();

        assert!(usize::from(end) <= len);

        // NOTE(cast) end <= self.len() (self.end) <= u8::MAX
        OwningSliceTo {
            buffer: self.buffer,
            end: end as u8,
        }
    }
}

impl<B> IntoSliceTo<u8> for OwningSliceTo<B, u16>
where
    B: AsSlice,
{
    type SliceTo = OwningSliceTo<B, u16>;

    fn into_slice_to(self, end: u8) -> Self::SliceTo {
        let len = self.len();

        assert!(usize::from(end) <= len);

        OwningSliceTo {
            buffer: self.buffer,
            end: u16::from(end),
        }
    }
}

impl<B, I> Truncate<I> for OwningSliceTo<B, I>
where
    B: AsSlice,
    I: sealed::Index,
{
    fn truncate(&mut self, len: I) {
        if len < self.end {
            self.end = len;
        }
    }
}

impl<B> Truncate<u16> for OwningSliceTo<B, u8>
where
    B: AsSlice,
{
    fn truncate(&mut self, len: u16) {
        if len < u16::from(self.end) {
            self.end = len as u8;
        }
    }
}

impl<B> Truncate<u8> for OwningSliceTo<B, u16>
where
    B: AsSlice,
{
    fn truncate(&mut self, len: u8) {
        let len = u16::from(len);

        if len < self.end {
            self.end = len;
        }
    }
}
