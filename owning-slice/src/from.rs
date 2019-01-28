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
    pub fn into_slice_from(self, start: I) -> OwningSliceFrom<B, I> {
        let len = self.len();
        let ustart = start.into();

        assert!(ustart <= len);

        OwningSliceFrom {
            buffer: self.buffer,
            start: self.start + start,
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
    type Output = OwningSlice<B, I>;

    fn into_slice(self, start: I, length: I) -> Self::Output {
        self.into_slice(start, length)
    }
}

impl<B, I> IntoSliceFrom<I> for OwningSliceFrom<B, I>
where
    B: AsSlice,
    I: sealed::Index,
{
    type OutputF = OwningSliceFrom<B, I>;

    fn into_slice_from(self, start: I) -> Self::OutputF {
        self.into_slice_from(start)
    }
}

impl<B, I> IntoSliceTo<I> for OwningSliceFrom<B, I>
where
    B: AsSlice,
    I: sealed::Index,
{
    type OutputT = OwningSlice<B, I>;

    fn into_slice_to(self, end: I) -> Self::OutputT {
        self.into_slice_to(end)
    }
}
