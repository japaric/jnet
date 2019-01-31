use core::{ops, slice};

use stable_deref_trait::StableDeref;

use crate::{
    sealed,
    traits::{IntoSlice, IntoSliceFrom, IntoSliceTo},
    AsMutSlice, AsSlice, OwningSlice,
};

/// Owning slice of a `BUFFER` where `end == buffer.len()`
#[derive(Clone, Copy)]
pub struct OwningSliceFrom<BUFFER, INDEX>
where
    BUFFER: AsSlice,
    INDEX: sealed::Index,
{
    pub(crate) buffer: BUFFER,
    pub(crate) start: INDEX,
}

/// Equivalent to `buffer[start..]` but by value
#[allow(non_snake_case)]
pub fn OwningSliceFrom<B, I>(buffer: B, start: I) -> OwningSliceFrom<B, I>
where
    B: AsSlice,
    I: sealed::Index,
{
    let blen = buffer.as_slice().len();
    let ustart = start.into();

    assert!(ustart <= blen && blen - ustart <= I::max());

    OwningSliceFrom { buffer, start }
}

impl<B, I> OwningSliceFrom<B, I>
where
    B: AsSlice,
    I: sealed::Index,
{
    /// Destroys the owning slice and returns the original buffer
    pub fn unslice(self) -> B {
        self.buffer
    }
}

impl<B, I> AsSlice for OwningSliceFrom<B, I>
where
    B: AsSlice,
    I: sealed::Index,
{
    type Element = B::Element;

    fn as_slice(&self) -> &[B::Element] {
        unsafe {
            let p = self.buffer.as_slice().as_ptr().add(self.start.into());
            let len = self.buffer.as_slice().len() - self.start.into();

            slice::from_raw_parts(p, len)
        }
    }
}

impl<B, I> AsMutSlice for OwningSliceFrom<B, I>
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
            let len = self.buffer.as_slice().len() - self.start.into();

            slice::from_raw_parts_mut(p, len)
        }
    }
}

impl<B, I> ops::Deref for OwningSliceFrom<B, I>
where
    B: AsSlice,
    I: sealed::Index,
{
    type Target = [B::Element];

    fn deref(&self) -> &[B::Element] {
        self.as_slice()
    }
}

impl<B, I> ops::DerefMut for OwningSliceFrom<B, I>
where
    B: AsMutSlice,
    I: sealed::Index,
{
    fn deref_mut(&mut self) -> &mut [B::Element] {
        self.as_mut_slice()
    }
}

unsafe impl<B, I> StableDeref for OwningSliceFrom<B, I>
where
    B: AsSlice + StableDeref,
    I: sealed::Index,
{
}

impl<B, I> IntoSlice<I> for OwningSliceFrom<B, I>
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

impl<B> IntoSlice<u16> for OwningSliceFrom<B, u8>
where
    B: AsSlice,
{
    type Slice = OwningSlice<B, u8>;

    fn into_slice(self, start: u16, length: u16) -> Self::Slice {
        let len = self.len();

        assert!(usize::from(start) + usize::from(length) <= len);

        // NOTE(cast) start, length < len <= u8::MAX
        OwningSlice {
            buffer: self.buffer,
            start: self.start + start as u8,
            length: length as u8,
        }
    }
}

impl<B> IntoSlice<u8> for OwningSliceFrom<B, u16>
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

impl<B, I> IntoSliceFrom<I> for OwningSliceFrom<B, I>
where
    B: AsSlice,
    I: sealed::Index,
{
    type SliceFrom = OwningSliceFrom<B, I>;

    fn into_slice_from(self, start: I) -> Self::SliceFrom {
        let len = self.len();
        let ustart = start.into();

        assert!(ustart <= len);

        OwningSliceFrom {
            buffer: self.buffer,
            start: self.start + start,
        }
    }
}

// we can't impl this because `self.len()` is unbounded (could be greater than `u8::MAX`)
// impl<B> IntoSliceFrom<u16> for OwningSliceFrom<B, u8> where B: AsSlice {}

impl<B> IntoSliceFrom<u8> for OwningSliceFrom<B, u16>
where
    B: AsSlice,
{
    type SliceFrom = OwningSliceFrom<B, u16>;

    fn into_slice_from(self, start: u8) -> Self::SliceFrom {
        let len = self.len();

        assert!(usize::from(start) <= len);

        OwningSliceFrom {
            buffer: self.buffer,
            start: self.start + u16::from(start),
        }
    }
}

impl<B, I> IntoSliceTo<I> for OwningSliceFrom<B, I>
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

// we can't impl this because `self.len()` is unbounded (could be greater than u8::MAX)
// impl<B> IntoSliceTo<u16> for OwningSliceFrom<B, u8> where B: AsSlice {}

impl<B> IntoSliceTo<u8> for OwningSliceFrom<B, u16>
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
            length: u16::from(end),
        }
    }
}
